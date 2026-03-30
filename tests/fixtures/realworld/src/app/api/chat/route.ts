// AI chat endpoint — no auth, key in code
import OpenAI from 'openai';

const openai = new OpenAI({
  apiKey: 'sk-proj-mykey1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef',
});

export async function POST(req: Request) {
  const { message } = await req.json();

  const response = await openai.chat.completions.create({
    model: 'gpt-4',
    messages: [
      { role: 'system', content: `You are a helpful assistant. The user said: ${message}` },
      { role: 'user', content: message },
    ],
  });

  return Response.json({ reply: response.choices[0].message.content });
}
