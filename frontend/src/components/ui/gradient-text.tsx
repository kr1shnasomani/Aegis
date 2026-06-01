import React from "react";
import { motion, type MotionProps } from "framer-motion";
import { cn } from "@/lib/utils";

interface GradientTextProps
  extends Omit<React.HTMLAttributes<HTMLElement>, keyof MotionProps> {
  className?: string;
  children: React.ReactNode;
  as?: React.ElementType;
}

const MotionComponents: Record<string, any> = {
  h1: motion.create("h1"),
  h2: motion.create("h2"),
  h3: motion.create("h3"),
  h4: motion.create("h4"),
  h5: motion.create("h5"),
  h6: motion.create("h6"),
  p: motion.create("p"),
  span: motion.create("span"),
  div: motion.create("div"),
};

function GradientText({
  className,
  children,
  as: Component = "span",
  ...props
}: GradientTextProps) {
  // Use a pre-created motion component to avoid unmounting on re-render
  const ComponentString = Component as string;
  const MotionComponent = MotionComponents[ComponentString] || MotionComponents.span;

  return (
    <MotionComponent
      className={cn(
        "bg-clip-text text-transparent animate-gradient",
        className
      )}
      style={{
        backgroundImage: "linear-gradient(90deg, #f472b6, #fbbf24, #60a5fa, #34d399, #f472b6)",
        backgroundSize: "300% 100%",
      }}
      {...props}
    >
      {children}
    </MotionComponent>
  );
}

export { GradientText };
