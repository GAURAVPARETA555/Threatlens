import * as React from "react";
import { Link, useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Shield, Lock, User, Mail, AlertCircle, CheckCircle2, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { registerSchema, type RegisterPayload } from "@/api/schemas";
import { register as registerApi } from "@/api/auth";

export function RegisterPage() {
  const navigate = useNavigate();
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);
  const [successMsg, setSuccessMsg] = React.useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<RegisterPayload>({
    resolver: zodResolver(registerSchema),
    defaultValues: {
      username: "",
      email: "",
      password: "",
    },
  });

  const onSubmit = async (data: RegisterPayload) => {
    try {
      setErrorMsg(null);
      await registerApi(data);
      setSuccessMsg("Account registered successfully! Redirecting to login...");
      setTimeout(() => {
        navigate("/login");
      }, 1500);
    } catch (err: unknown) {
      if (typeof err === "object" && err !== null && "response" in err) {
        const resp = (err as { response?: { data?: Record<string, string[] | string> } }).response;
        const msg = resp?.data
          ? Object.entries(resp.data)
              .map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : v}`)
              .join(" | ")
          : "Registration failed.";
        setErrorMsg(msg);
      } else {
        setErrorMsg("Failed to connect to registration service.");
      }
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-background p-4">
      <Card className="w-full max-w-sm border-border bg-card shadow-none">
        <CardHeader className="space-y-1 pb-4">
          <div className="flex items-center gap-2 mb-2">
            <div className="flex h-7 w-7 items-center justify-center rounded bg-teal-500/10 text-teal-400 border border-teal-500/20">
              <Shield className="h-4 w-4" />
            </div>
            <span className="text-xs font-mono font-bold tracking-wider uppercase text-foreground">
              ThreatLens Console
            </span>
          </div>
          <CardTitle className="text-lg font-bold tracking-tight">Register Operator</CardTitle>
          <CardDescription className="text-xs text-muted-foreground">
            Create an account to observe security telemetry (defaults to viewer role).
          </CardDescription>
        </CardHeader>

        <CardContent>
          {errorMsg && (
            <div className="mb-4 flex items-center gap-2 rounded border border-severity-critical/20 bg-severity-critical/10 p-2.5 text-xs text-severity-critical">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{errorMsg}</span>
            </div>
          )}

          {successMsg && (
            <div className="mb-4 flex items-center gap-2 rounded border border-teal-500/20 bg-teal-500/10 p-2.5 text-xs text-teal-400">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              <span>{successMsg}</span>
            </div>
          )}

          <form onSubmit={handleSubmit(onSubmit)} className="space-y-3.5">
            <div className="space-y-1.5">
              <Label htmlFor="username" className="text-xs font-medium">
                Username
              </Label>
              <div className="relative">
                <Input
                  id="username"
                  placeholder="soc_operator"
                  autoComplete="username"
                  className="h-8 pl-8 text-xs font-mono border-border bg-muted/20"
                  {...register("username")}
                />
                <User className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              </div>
              {errors.username && (
                <p className="text-[11px] text-severity-critical">{errors.username.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="email" className="text-xs font-medium">
                Email Address
              </Label>
              <div className="relative">
                <Input
                  id="email"
                  type="email"
                  placeholder="analyst@enterprise.internal"
                  autoComplete="email"
                  className="h-8 pl-8 text-xs font-mono border-border bg-muted/20"
                  {...register("email")}
                />
                <Mail className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              </div>
              {errors.email && (
                <p className="text-[11px] text-severity-critical">{errors.email.message}</p>
              )}
            </div>

            <div className="space-y-1.5">
              <Label htmlFor="password" className="text-xs font-medium">
                Password
              </Label>
              <div className="relative">
                <Input
                  id="password"
                  type="password"
                  placeholder="••••••••"
                  autoComplete="new-password"
                  className="h-8 pl-8 text-xs font-mono border-border bg-muted/20"
                  {...register("password")}
                />
                <Lock className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground" />
              </div>
              {errors.password && (
                <p className="text-[11px] text-severity-critical">{errors.password.message}</p>
              )}
            </div>

            <Button
              type="submit"
              disabled={isSubmitting}
              className="w-full h-8 bg-teal-600 hover:bg-teal-500 text-white text-xs font-medium gap-1.5"
            >
              {isSubmitting ? (
                <>
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  <span>Registering...</span>
                </>
              ) : (
                <span>Create Operator Account</span>
              )}
            </Button>
          </form>

          <div className="mt-4 text-center text-xs text-muted-foreground border-t border-border pt-3">
            Already have an account?{" "}
            <Link to="/login" className="text-teal-400 hover:underline font-medium">
              Sign in
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
