/**
 * Optional WebGPU compute offload for globe arc sample projection.
 * Non-breaking: callers must keep the CPU path as fallback (see CobeGlobe).
 *
 * Pipeline: unit-sphere samples (xyz) + rotation uniforms → screen (x,y,visible,depth).
 */

export type ArcGpuUniforms = {
  cosPhi: number;
  sinPhi: number;
  cosTheta: number;
  sinTheta: number;
  radius: number;
  half: number;
  minDepth: number;
};

export type ArcGpuStatus =
  | "unchecked"
  | "unavailable"
  | "initializing"
  | "ready"
  | "failed";

const SHADER = /* wgsl */ `
struct Uniforms {
  cosPhi: f32,
  sinPhi: f32,
  cosTheta: f32,
  sinTheta: f32,
  radius: f32,
  half: f32,
  minDepth: f32,
  count: u32,
}

struct InVec {
  x: f32,
  y: f32,
  z: f32,
  _pad: f32,
}

struct OutPoint {
  x: f32,
  y: f32,
  visible: f32,
  depth: f32,
}

@group(0) @binding(0) var<uniform> u: Uniforms;
@group(0) @binding(1) var<storage, read> inputs: array<InVec>;
@group(0) @binding(2) var<storage, read_write> outputs: array<OutPoint>;

@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let i = gid.x;
  if (i >= u.count) {
    return;
  }
  let v = inputs[i];
  let x = v.x * u.cosPhi + v.z * u.sinPhi;
  let y = v.x * u.sinPhi * u.sinTheta + v.y * u.cosTheta - v.z * u.cosPhi * u.sinTheta;
  let depth = -v.x * u.sinPhi * u.cosTheta + v.y * u.sinTheta + v.z * u.cosPhi * u.cosTheta;
  outputs[i].x = u.half + x * u.radius;
  outputs[i].y = u.half - y * u.radius;
  outputs[i].visible = select(0.0, 1.0, depth > u.minDepth);
  outputs[i].depth = depth;
}
`;

/** Pack vec3 samples as 4-float structs (16-byte aligned for WGSL). */
export function packSamplesForGpu(
  samples: Array<{ x: number; y: number; z: number }>,
): Float32Array {
  const out = new Float32Array(samples.length * 4);
  for (let i = 0; i < samples.length; i += 1) {
    const s = samples[i];
    const o = i * 4;
    out[o] = s.x;
    out[o + 1] = s.y;
    out[o + 2] = s.z;
    out[o + 3] = 0;
  }
  return out;
}

/**
 * Build SVG path `d` from GPU output (x,y,visible,depth per point).
 * Mirrors CPU buildProjectedPath segmentation rules.
 */
export function pathFromGpuOutput(
  out: Float32Array,
  start: number,
  count: number,
): string {
  let d = "";
  let drawing = false;
  let visibleCount = 0;
  for (let i = 0; i < count; i += 1) {
    const base = (start + i) * 4;
    const visible = out[base + 2] > 0.5;
    if (!visible) {
      drawing = false;
      continue;
    }
    visibleCount += 1;
    const px = Math.round(out[base] * 10) / 10;
    const py = Math.round(out[base + 1] * 10) / 10;
    d += `${drawing ? "L" : "M"}${px} ${py} `;
    drawing = true;
  }
  return visibleCount >= 2 ? d.trim() : "";
}

export class ArcGpuProjector {
  status: ArcGpuStatus = "unchecked";
  private device: GPUDevice | null = null;
  private pipeline: GPUComputePipeline | null = null;
  private bindGroupLayout: GPUBindGroupLayout | null = null;
  private uniformBuffer: GPUBuffer | null = null;
  private inputBuffer: GPUBuffer | null = null;
  private outputBuffer: GPUBuffer | null = null;
  private stagingBuffer: GPUBuffer | null = null;
  private capacity = 0;
  private busy = false;
  private initPromise: Promise<boolean> | null = null;

  isReady() {
    return this.status === "ready" && this.device != null && this.pipeline != null;
  }

  isBusy() {
    return this.busy;
  }

  /** Lazy init — safe to call many times. */
  ensureReady(): Promise<boolean> {
    if (this.status === "ready") return Promise.resolve(true);
    if (this.status === "unavailable" || this.status === "failed") {
      return Promise.resolve(false);
    }
    if (this.initPromise) return this.initPromise;

    this.status = "initializing";
    this.initPromise = this.initInternal().then((ok) => {
      this.status = ok ? "ready" : "unavailable";
      if (!ok) this.initPromise = null;
      return ok;
    });
    return this.initPromise;
  }

  private async initInternal(): Promise<boolean> {
    try {
      const nav = navigator as Navigator & { gpu?: GPU };
      if (!nav.gpu) return false;
      const adapter = await nav.gpu.requestAdapter({
        powerPreference: "high-performance",
      });
      if (!adapter) return false;
      const device = await adapter.requestDevice();
      device.lost.then(() => {
        this.status = "failed";
        this.device = null;
        this.pipeline = null;
      });

      const module = device.createShaderModule({ code: SHADER });
      const bindGroupLayout = device.createBindGroupLayout({
        entries: [
          {
            binding: 0,
            visibility: GPUShaderStage.COMPUTE,
            buffer: { type: "uniform" },
          },
          {
            binding: 1,
            visibility: GPUShaderStage.COMPUTE,
            buffer: { type: "read-only-storage" },
          },
          {
            binding: 2,
            visibility: GPUShaderStage.COMPUTE,
            buffer: { type: "storage" },
          },
        ],
      });
      const pipeline = device.createComputePipeline({
        layout: device.createPipelineLayout({
          bindGroupLayouts: [bindGroupLayout],
        }),
        compute: { module, entryPoint: "main" },
      });

      this.device = device;
      this.pipeline = pipeline;
      this.bindGroupLayout = bindGroupLayout;
      this.uniformBuffer = device.createBuffer({
        size: 32, // 7xf32 + 1xu32 = 32 bytes
        usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST,
      });
      return true;
    } catch {
      this.status = "failed";
      return false;
    }
  }

  private ensureCapacity(count: number) {
    const device = this.device;
    if (!device || count <= this.capacity) return;
    // Grow with headroom
    const next = Math.max(256, count * 2);
    this.inputBuffer?.destroy();
    this.outputBuffer?.destroy();
    this.stagingBuffer?.destroy();
    const inBytes = next * 16;
    const outBytes = next * 16;
    this.inputBuffer = device.createBuffer({
      size: inBytes,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST,
    });
    this.outputBuffer = device.createBuffer({
      size: outBytes,
      usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC,
    });
    this.stagingBuffer = device.createBuffer({
      size: outBytes,
      usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
    });
    this.capacity = next;
  }

  /**
   * Project packed samples. Returns Float32Array of length count*4
   * (x, y, visible, depth) or null on failure / busy.
   */
  async project(
    packedXyzPad: Float32Array,
    uniforms: ArcGpuUniforms,
  ): Promise<Float32Array | null> {
    if (this.busy) return null;
    const ok = await this.ensureReady();
    if (!ok || !this.device || !this.pipeline || !this.bindGroupLayout) {
      return null;
    }
    if (!this.uniformBuffer) return null;

    const count = Math.floor(packedXyzPad.length / 4);
    if (count <= 0) return new Float32Array(0);

    this.busy = true;
    try {
      this.ensureCapacity(count);
      const device = this.device;
      const inputBuffer = this.inputBuffer!;
      const outputBuffer = this.outputBuffer!;
      const stagingBuffer = this.stagingBuffer!;
      const uniformBuffer = this.uniformBuffer;

      const uData = new ArrayBuffer(32);
      const uF = new Float32Array(uData, 0, 7);
      const uU = new Uint32Array(uData, 28, 1);
      uF[0] = uniforms.cosPhi;
      uF[1] = uniforms.sinPhi;
      uF[2] = uniforms.cosTheta;
      uF[3] = uniforms.sinTheta;
      uF[4] = uniforms.radius;
      uF[5] = uniforms.half;
      uF[6] = uniforms.minDepth;
      uU[0] = count;

      device.queue.writeBuffer(uniformBuffer, 0, uData);
      device.queue.writeBuffer(
        inputBuffer,
        0,
        packedXyzPad.buffer,
        packedXyzPad.byteOffset,
        count * 16,
      );

      const bindGroup = device.createBindGroup({
        layout: this.bindGroupLayout,
        entries: [
          { binding: 0, resource: { buffer: uniformBuffer } },
          { binding: 1, resource: { buffer: inputBuffer } },
          { binding: 2, resource: { buffer: outputBuffer } },
        ],
      });

      const encoder = device.createCommandEncoder();
      const pass = encoder.beginComputePass();
      pass.setPipeline(this.pipeline);
      pass.setBindGroup(0, bindGroup);
      pass.dispatchWorkgroups(Math.ceil(count / 64));
      pass.end();
      encoder.copyBufferToBuffer(outputBuffer, 0, stagingBuffer, 0, count * 16);
      device.queue.submit([encoder.finish()]);

      await stagingBuffer.mapAsync(GPUMapMode.READ, 0, count * 16);
      const copy = new Float32Array(count * 4);
      copy.set(new Float32Array(stagingBuffer.getMappedRange(0, count * 16)));
      stagingBuffer.unmap();
      return copy;
    } catch {
      this.status = "failed";
      return null;
    } finally {
      this.busy = false;
    }
  }

  dispose() {
    this.inputBuffer?.destroy();
    this.outputBuffer?.destroy();
    this.stagingBuffer?.destroy();
    this.uniformBuffer?.destroy();
    this.device?.destroy();
    this.device = null;
    this.pipeline = null;
    this.status = "unavailable";
    this.capacity = 0;
  }
}

/** Shared singleton — one device for the globe page. */
let shared: ArcGpuProjector | null = null;

export function getArcGpuProjector(): ArcGpuProjector {
  if (!shared) shared = new ArcGpuProjector();
  return shared;
}
