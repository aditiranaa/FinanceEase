import { useEffect, useState } from "react";

import {
  analyzeFinances,
  getHistory,
  deleteHistory,
} from "../services/aiService";

export default function useAI() {
  const [history, setHistory] = useState([]);
  const [analysis, setAnalysis] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadHistory = async () => {
    try {
      const data = await getHistory();
      setHistory(data);
    } catch (err) {
      console.error(err);
      setError("Failed to load AI history.");
    }
  };

  const analyze = async () => {
    try {
      setLoading(true);

      const data = await analyzeFinances();

      setAnalysis(data.response);

      await loadHistory();
    } catch (err) {
      console.error(err);
      setError("Failed to generate AI analysis.");
    } finally {
      setLoading(false);
    }
  };

  const removeHistory = async (id) => {
    await deleteHistory(id);

    setHistory((prev) =>
      prev.filter((item) => item.id !== id)
    );
  };

  useEffect(() => {
    loadHistory();
  }, []);

  return {
    history,
    analysis,
    loading,
    error,
    analyze,
    removeHistory,
  };
}