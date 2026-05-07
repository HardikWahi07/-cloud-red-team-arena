import { motion } from 'framer-motion';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export const GlassCard = ({ children, className, glow = false }: { children: React.ReactNode, className?: string, glow?: boolean }) => (
  <motion.div
    initial={{ opacity: 0, y: 20 }}
    animate={{ opacity: 1, y: 0 }}
    className={cn(
      "glass-panel p-6 overflow-hidden relative",
      glow && "neon-glow border-neon-blue/30",
      className
    )}
  >
    {children}
  </motion.div>
);

export const NeonButton = ({ children, onClick, className, variant = 'blue' }: {
  children: React.ReactNode,
  onClick?: () => void,
  className?: string,
  variant?: 'blue' | 'purple' | 'green' | 'red'
}) => {
  const variantClasses = {
    blue: "border-neon-blue text-neon-blue hover:bg-neon-blue/10",
    purple: "border-neon-purple text-neon-purple hover:bg-neon-purple/10",
    green: "border-neon-green text-neon-green hover:bg-neon-green/10",
    red: "border-neon-red text-neon-red hover:bg-neon-red/10",
  };

  return (
    <button
      onClick={onClick}
      className={cn(
        "px-6 py-2 border rounded-md uppercase tracking-widest text-xs transition-all duration-300 font-bold",
        variantClasses[variant],
        className
      )}
    >
      {children}
    </button>
  );
};

export const StatusBadge = ({ status }: { status: string }) => {
  const colors: Record<string, string> = {
    pending: "text-yellow-400 bg-yellow-400/10 border-yellow-400/20",
    in_progress: "text-neon-blue bg-neon-blue/10 border-neon-blue/20",
    completed: "text-neon-green bg-neon-green/10 border-neon-green/20",
    blocked: "text-neon-red bg-neon-red/10 border-neon-red/20",
  };

  return (
    <span className={cn("px-2 py-1 rounded text-[10px] font-bold border uppercase", colors[status] || colors.pending)}>
      {status}
    </span>
  );
};
