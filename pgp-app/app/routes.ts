import { type RouteConfig, index, route } from "@react-router/dev/routes";

export default [
  index("routes/home.tsx"),
  route("api/keybase", "routes/api.keybase.ts"),
  route("api/keybase/getsalt", "routes/api.keybase.getsalt.ts"),
  route("api/keybase/login", "routes/api.keybase.login.ts"),
  route("api/keybase/autocomplete", "routes/api.keybase.autocomplete.ts"),
  route("api/keybase/fetchkey", "routes/api.keybase.fetchkey.ts"),
  route("api/keybase/fetchkey-opg", "routes/api.keybase.fetchkey-opg.ts"),
] satisfies RouteConfig;
