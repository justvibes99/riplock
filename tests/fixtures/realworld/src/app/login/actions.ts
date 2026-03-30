'use server';

import { prisma } from '@/lib/db';
import jwt from 'jsonwebtoken';
import { cookies } from 'next/headers';

export async function login(formData: FormData) {
  const email = formData.get('email') as string;
  const password = formData.get('password') as string;

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || user.password !== password) {
    return { error: 'Invalid credentials' };
  }

  const token = jwt.sign({ userId: user.id }, 'my-jwt-secret');
  cookies().set('token', token);

  return { success: true };
}
