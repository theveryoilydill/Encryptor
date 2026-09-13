import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import { ThemeProvider } from "next-themes";
import "./globals.css";

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
	keywords: ["PGP", "encryption", "encryptor", "keybase"],
	authors: [{ name: "Encryptor" }],
	icons: {
		icon: "/logo.svg",
	},
	openGraph: {
		title: "Encryptor",
		description: "Use public PGP registries to encrypt messages to friends.",
		siteName: "Encryptor",
		type: "website",
	},
	twitter: {
		card: "summary_large_image",
		title: "Encryptor",
		description: "Use public PGP registries to encrypt messages to friends.",
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
				className={`${geistSans.variable} ${geistMono.variable} antialiased min-h-screen flex flex-col bg-background text-foreground font-sans`}
			>
				<ThemeProvider
					attribute="class"
					defaultTheme="system"
					enableSystem
					disableTransitionOnChange
				>
					{children}
				</ThemeProvider>
			</body>
		</html>
	);
}
