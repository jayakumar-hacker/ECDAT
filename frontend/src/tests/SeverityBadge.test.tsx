import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import SeverityBadge from "../components/SeverityBadge";

describe("SeverityBadge", () => {
  it("renders the severity text", () => {
    render(<SeverityBadge severity="CRITICAL" />);
    expect(screen.getByText("CRITICAL")).toBeInTheDocument();
  });

  it("applies the matching severity class", () => {
    render(<SeverityBadge severity="HIGH" />);
    expect(screen.getByText("HIGH").className).toContain("badge-HIGH");
  });
});
