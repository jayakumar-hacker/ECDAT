import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import StatCard from "../components/StatCard";

describe("StatCard", () => {
  it("renders label and value", () => {
    render(<StatCard label="Total Assets" value={42} />);
    expect(screen.getByText("Total Assets")).toBeInTheDocument();
    expect(screen.getByText("42")).toBeInTheDocument();
  });
});
