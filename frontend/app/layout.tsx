import type { Metadata } from "next";
import "./globals.css";
import { WorkspaceProvider } from "@/components/Workspace";
import { Shell } from "@/components/Shell";

export const metadata: Metadata = {
  title: "AegisRMF",
  description: "CMMC readiness workspace: evidence, findings, scoring and POA&M.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="antialiased">
        <WorkspaceProvider>
          <Shell>{children}</Shell>
        </WorkspaceProvider>
      </body>
    </html>
  );
}
