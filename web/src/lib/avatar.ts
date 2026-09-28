/**
 * A profile picture, made small in the browser before it goes up: the middle square of the
 * photo, 256 × 256, as a JPEG. The server only stores what it gets, so a 12-megapixel phone
 * photo never leaves the phone.
 */

export const AVATAR_SIZE = 256;

/** The largest centred square of a `width` × `height` picture. */
export function centreSquare(width: number, height: number) {
  const side = Math.min(width, height);
  return { x: (width - side) / 2, y: (height - side) / 2, side };
}

export async function squareJpeg(file: Blob, size = AVATAR_SIZE): Promise<Blob> {
  const bitmap = await createImageBitmap(file);
  try {
    const { x, y, side } = centreSquare(bitmap.width, bitmap.height);
    const canvas = document.createElement('canvas');
    canvas.width = size;
    canvas.height = size;
    const context = canvas.getContext('2d');
    if (!context) throw new Error('No canvas.');
    // A transparent PNG would turn black as a JPEG; white is what it looks like on the page.
    context.fillStyle = '#ffffff';
    context.fillRect(0, 0, size, size);
    context.imageSmoothingQuality = 'high';
    context.drawImage(bitmap, x, y, side, side, 0, 0, size, size);
    return await new Promise<Blob>((resolve, reject) =>
      canvas.toBlob(
        (blob) => (blob ? resolve(blob) : reject(new Error('No picture.'))),
        'image/jpeg',
        0.85,
      ),
    );
  } finally {
    bitmap.close();
  }
}
