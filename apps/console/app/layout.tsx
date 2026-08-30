import type { Metadata } from 'next';
import './globals.css';

const title = 'RetryWise — Governed Payment Recovery';
const description =
  'Payment recovery that knows when to act—and when to stop. Real Razorpay Test Mode effects, policy-bounded decisions, and cryptographically verifiable outcomes.';

export const metadata: Metadata = {
  metadataBase: new URL(process.env.RETRYWISE_SITE_URL ?? 'http://localhost:3000'),
  title,
  description,
  openGraph: {
    type: 'website',
    title,
    description,
    images: [{
      url: '/og.png',
      width: 1200,
      height: 630,
      alt: 'RetryWise turns a failed payment into governed, verified recovery.',
    }],
  },
  twitter: {
    card: 'summary_large_image',
    title,
    description,
    images: ['/og.png'],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
