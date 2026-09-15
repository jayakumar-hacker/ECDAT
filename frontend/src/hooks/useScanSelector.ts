import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import api from "../services/api";
import type { Scan } from "../types";

export function useScanSelector() {
  const [searchParams, setSearchParams] = useSearchParams();
  const [scans, setScans] = useState<Scan[]>([]);
  const scanId = searchParams.get("scan_id") || "";

  useEffect(() => {
    api.get("/scans").then((res) => {
      setScans(res.data);
      if (!scanId && res.data.length > 0) {
        setSearchParams({ scan_id: res.data[0].id });
      }
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function setScanId(id: string) {
    setSearchParams({ scan_id: id });
  }

  return { scanId, scans, setScanId };
}
