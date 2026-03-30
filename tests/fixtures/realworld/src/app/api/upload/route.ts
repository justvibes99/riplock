// File upload — no validation
import { writeFile } from 'fs/promises';
import path from 'path';

export async function POST(req: Request) {
  const formData = await req.formData();
  const file = formData.get('file') as File;
  const bytes = await file.arrayBuffer();
  const buffer = Buffer.from(bytes);

  const uploadPath = path.join('public/uploads', file.name);
  await writeFile(uploadPath, buffer);

  return Response.json({ url: `/uploads/${file.name}` });
}
