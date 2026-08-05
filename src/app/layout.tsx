import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/toaster";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Encryptor",
  description: "Use public PGP registries to encrypt messages to friends.",
  keywords: ["PGP", "encryption", "encryptor"],
  authors: [{ name: "Encryptor" }],
  icons: {
    icon: "/logo.svg",
  },
  openGraph: {
    title: "Encryptor",
    description: "Browser-based PGP encryption with Keybase lookup.",
    url: "https://example.com",
    siteName: "Encryptor",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Encryptor",
    description: "Browser-based PGP encryption with Keybase lookup.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        {children}
        <Toaster />
      </body>
    </html>
  );
}
