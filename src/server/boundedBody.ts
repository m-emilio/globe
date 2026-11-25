export class BodyLimitError extends Error {}

export async function readBoundedText(body: ReadableStream<Uint8Array> | null, limit: number): Promise<string> {
  if (!body) throw new Error("Missing response body.");
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let size = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return text + decoder.decode();
      size += value.byteLength;
      if (size > limit) {
        await reader.cancel().catch(() => {});
        throw new BodyLimitError("Size limit exceeded.");
      }
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    reader.releaseLock();
  }
}
