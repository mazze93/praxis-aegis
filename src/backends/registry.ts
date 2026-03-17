import { type HttpBackend, invokeHttpBackend } from "./http.js";

export type { HttpBackend };

export type ToolInvocationContext = {
  requestId: string;
  identity: string;
  policySetId: string;
  tierId: string;
  callerType: "model" | "code_execution";
};

export type LocalHandler = (
  toolName: string,
  input: unknown,
  context: ToolInvocationContext
) => Promise<unknown>;

export interface LocalBackend {
  type: "local";
  handler: LocalHandler;
}

export type Backend = HttpBackend | LocalBackend;

export interface ToolRoute {
  /** Exact tool name or regex pattern. First match wins. */
  match: string | RegExp;
  backend: Backend;
}

export class ToolRouter {
  private routes: ToolRoute[] = [];

  register(route: ToolRoute): void {
    this.routes.push(route);
  }

  async dispatch(
    toolName: string,
    input: unknown,
    context: ToolInvocationContext
  ): Promise<unknown> {
    for (const route of this.routes) {
      const matched =
        typeof route.match === "string"
          ? route.match === toolName
          : route.match.test(toolName);

      if (!matched) continue;

      if (route.backend.type === "http") {
        return invokeHttpBackend(route.backend, toolName, input, context);
      } else {
        return route.backend.handler(toolName, input, context);
      }
    }

    throw new Error(`No backend registered for tool: ${toolName}`);
  }
}
