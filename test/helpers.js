export function bytesHex(u8) {
  let out = '';
  for (const b of u8) out += b.toString(16).padStart(2, '0');
  return out;
}
