'use server';

import { prisma } from '@/lib/db';

export async function updateProfile(formData: FormData) {
  const name = formData.get('name') as string;
  const email = formData.get('email') as string;

  await prisma.user.update({
    where: { email },
    data: { name, email },
  });
}

export async function deleteAccount(formData: FormData) {
  const userId = formData.get('userId') as string;
  await prisma.user.delete({ where: { id: userId } });
}
