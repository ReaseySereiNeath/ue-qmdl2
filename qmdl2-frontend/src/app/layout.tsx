import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "QMDL2 Log Viewer",
  description: "Decode and analyze Qualcomm QMDL2 5G diagnostic logs",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style dangerouslySetInnerHTML={{ __html: `
          :root {
            --font-inter: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            --font-mono: 'Cascadia Code', 'Fira Code', 'SF Mono', 'Consolas', monospace;
          }
        `}} />
      </head>
      <body className="antialiased" style={{ fontFamily: "var(--font-inter)" }}>
        {children}
      </body>
    </html>
  );
}
