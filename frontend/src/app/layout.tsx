import type { Metadata } from "next";
import "./globals.css";
import Sidebar from "@/components/Sidebar";
import TopBar from "@/components/TopBar";

export const metadata: Metadata = {
  title: "JDP Route Intelligence Platform | NOC Carrier Analytics",
  description: "Self-hosted high-rate flow analyzer, BGP optimization, and network route intelligence platform.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="bg-[#0B0F19] text-gray-100 min-h-screen">
        <Sidebar />
        <div className="pl-64 flex flex-col min-h-screen">
          <TopBar />
          <main className="flex-1 p-6 max-w-7xl w-full mx-auto">{children}</main>
        </div>
      </body>
    </html>
  );
}
