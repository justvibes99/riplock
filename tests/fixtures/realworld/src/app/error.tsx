'use client';

export default function ErrorPage({ error }: { error: Error }) {
  return (
    <div>
      <h1>Something went wrong</h1>
      <p>{error.message}</p>
      <pre>{error.stack}</pre>
    </div>
  );
}
