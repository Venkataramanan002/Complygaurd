import { test, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

// Read the admin password from the repo-root .env — never hardcode credentials
const ADMIN_PASSWORD = (() => {
  const envFile = fs.readFileSync(path.resolve(process.cwd(), "../.env"), "utf-8");
  const m = envFile.match(/^DEFAULT_ADMIN_PASSWORD=(.*)$/m);
  if (!m) throw new Error("DEFAULT_ADMIN_PASSWORD not found in ../.env");
  return m[1].trim();
})();

test("unauthenticated visit redirects to login", async ({ page }) => {
  await page.goto("/");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByText("Sign in to continue")).toBeVisible();
});

test("login with default admin reaches dashboard, logout returns to login", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "Sign in" }).click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByText("Fortress Lens")).toBeVisible();

  await page.getByRole("button", { name: "Log out" }).click();
  await expect(page).toHaveURL(/\/login$/);
});

test("wrong password shows error", async ({ page }) => {
  await page.goto("/login");
  await page.getByLabel("Username").fill("admin");
  await page.getByLabel("Password").fill("definitely-wrong");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByText("Invalid username or password")).toBeVisible();
});
