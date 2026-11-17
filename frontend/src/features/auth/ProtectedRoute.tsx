import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { Skeleton } from "@/components/ui/skeleton";
import { ShieldAlert } from "lucide-react";

interface ProtectedRouteProps {
  requiredRole?: "admin" | "analyst" | "viewer";
}

export function ProtectedRoute({ requiredRole }: ProtectedRouteProps) {
  const { isAuthenticated, isLoading, user } = useAuth();
  const location = useLocation();

  if (isLoading) {
    return (
      <div className="flex h-screen w-screen items-center justify-center bg-background">
        <div className="flex flex-col items-center gap-3">
          <Skeleton className="h-8 w-8 rounded-full" />
          <Skeleton className="h-4 w-32" />
        </div>
      </div>
    );
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // Role hierarchy: admin > analyst > viewer
  if (requiredRole && user) {
    const roleHierarchy = { admin: 3, analyst: 2, viewer: 1 };
    const userLevel = roleHierarchy[user.role] ?? 1;
    const requiredLevel = roleHierarchy[requiredRole] ?? 1;

    if (userLevel < requiredLevel) {
      return (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <div className="flex h-12 w-12 items-center justify-center rounded-md bg-amber-500/10 text-amber-500 mb-3 border border-amber-500/20">
            <ShieldAlert className="h-6 w-6" />
          </div>
          <h2 className="text-sm font-semibold text-foreground">Access Restricted</h2>
          <p className="mt-1 text-xs text-muted-foreground max-w-sm">
            Insufficient permissions. Your current role is{" "}
            <span className="font-mono font-medium text-foreground">{user.role}</span>, but this
            action requires <span className="font-mono font-medium text-foreground">{requiredRole}</span> privileges.
          </p>
        </div>
      );
    }
  }

  return <Outlet />;
}
