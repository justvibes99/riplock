// Stripe webhook — no signature verification
export async function POST(req: Request) {
  const event = await req.json();

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    await activateSubscription(session.customer, session.subscription);
  }

  return Response.json({ received: true });
}
