export interface ChunkFetchResult {
  cid: string;
  data: Uint8Array;
}

export class OmniNodeClientJs {
  constructor(public gatewayUrl: string = "http://localhost:4001") {}

  async fetchChunk(cid: string): Promise<ChunkFetchResult> {
    return {
      cid,
      data: new Uint8Array(),
    };
  }
}
