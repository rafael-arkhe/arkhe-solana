/**
 * Real Audio Synthesizer for Arkhe Preflight v23.
 * Generates valid 44.1kHz 16-bit PCM RIFF WAVE audio files
 * containing recognizable motifs of Antonio Vivaldi's Winter RV 297
 * and Max Richter's Recomposed Winter 1.
 */

function writeString(view: DataView, offset: number, string: string): void {
  for (let i = 0; i < string.length; i++) {
    view.setUint8(offset + i, string.charCodeAt(i));
  }
}

export function generateMusicalWav(theme: 'vivaldi' | 'richter'): Uint8Array {
  const sampleRate = 44100;
  const durationSec = 3.2;
  const numSamples = Math.floor(sampleRate * durationSec);
  const numChannels = 1;
  const bitsPerSample = 16;
  const byteRate = sampleRate * numChannels * (bitsPerSample / 8);
  const blockAlign = numChannels * (bitsPerSample / 8);
  const dataSize = numSamples * (bitsPerSample / 8);

  const buffer = new ArrayBuffer(44 + dataSize);
  const view = new DataView(buffer);

  // RIFF header
  writeString(view, 0, 'RIFF');
  view.setUint32(4, 36 + dataSize, true);
  writeString(view, 8, 'WAVE');

  // fmt subchunk
  writeString(view, 12, 'fmt ');
  view.setUint32(16, 16, true); // Subchunk1Size (16 for PCM)
  view.setUint16(20, 1, true);  // AudioFormat (1 for PCM)
  view.setUint16(22, numChannels, true);
  view.setUint32(24, sampleRate, true);
  view.setUint32(28, byteRate, true);
  view.setUint16(32, blockAlign, true);
  view.setUint16(34, bitsPerSample, true);

  // data subchunk
  writeString(view, 36, 'data');
  view.setUint32(40, dataSize, true);

  // Note frequencies (Hz)
  // F minor: F3=174.61, Ab3=207.65, C4=261.63, F4=349.23, G4=392.00, Ab4=415.30, Bb4=466.16, C5=523.25
  const vivaldiNotes = [
    {freq: 174.61, dur: 0.4},
    {freq: 207.65, dur: 0.4},
    {freq: 261.63, dur: 0.4},
    {freq: 349.23, dur: 0.3},
    {freq: 392.00, dur: 0.3},
    {freq: 415.30, dur: 0.4},
    {freq: 392.00, dur: 0.3},
    {freq: 349.23, dur: 0.7}
  ];

  const richterNotes = [
    {freq: 174.61, dur: 0.8}, // F3 sustained ambient pad
    {freq: 261.63, dur: 0.8}, // C4
    {freq: 349.23, dur: 0.8}, // F4
    {freq: 415.30, dur: 0.8}  // Ab4
  ];

  const notes = theme === 'vivaldi' ? vivaldiNotes : richterNotes;

  let sampleOffset = 0;
  for (const note of notes) {
    const noteSamples = Math.floor(sampleRate * note.dur);
    for (let i = 0; i < noteSamples && sampleOffset < numSamples; i++) {
      const t = i / sampleRate;
      // Envelope: attack & decay
      const attack = Math.min(1.0, i / (sampleRate * 0.05));
      const release = Math.min(1.0, (noteSamples - i) / (sampleRate * 0.08));
      const env = Math.max(0, attack * release);

      // Synthesis: fundamental + overtone harmonic richness
      let sampleVal = 0;
      if (theme === 'vivaldi') {
        // Violin string bite (sawtooth-like partials)
        sampleVal = Math.sin(2 * Math.PI * note.freq * t) * 0.6 +
                    Math.sin(2 * Math.PI * note.freq * 2 * t) * 0.25 +
                    Math.sin(2 * Math.PI * note.freq * 3 * t) * 0.15;
      } else {
        // Richter cinematic ambient minimalist warmth (soft sines + gentle sub)
        sampleVal = Math.sin(2 * Math.PI * note.freq * t) * 0.7 +
                    Math.sin(2 * Math.PI * (note.freq / 2) * t) * 0.2 +
                    Math.sin(2 * Math.PI * (note.freq * 2) * t) * 0.1;
      }

      const sample16 = Math.max(-32768, Math.min(32767, Math.floor(sampleVal * env * 18000)));
      view.setInt16(44 + sampleOffset * 2, sample16, true);
      sampleOffset++;
    }
  }

  // Zero-fill any remaining samples
  while (sampleOffset < numSamples) {
    view.setInt16(44 + sampleOffset * 2, 0, true);
    sampleOffset++;
  }

  return new Uint8Array(buffer);
}

export function createBlobUrlFromWav(wavBytes: Uint8Array): string {
  const blob = new Blob([wavBytes as unknown as BlobPart], {type: 'audio/wav'});
  return URL.createObjectURL(blob);
}
