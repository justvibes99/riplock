// Typical vibe-coded API route — no auth, returns full objects
import { prisma } from '@/lib/db';

export async function GET() {
  const users = await prisma.user.findMany();
  return Response.json(users);
}

export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  await prisma.user.delete({ where: { id: params.id } });
  return Response.json({ ok: true });
}
