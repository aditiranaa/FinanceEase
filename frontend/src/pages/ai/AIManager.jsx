import AIChat from "../../components/ai/AIChat";
import AIOverview from "../../components/ai/AIOverview";
import AIHistory from "../../components/ai/AIHistory";
import AISuggestions from "../../components/ai/AISuggestions";
import MonthlySummary from "../../components/ai/MonthlySummary";

export default function AIManager({
  overview,
  analysis,
  history,
  loading,
  analyze,
  removeHistory,
}) {
  return (
    <div className="space-y-8">

      <AIChat
        analyze={analyze}
        loading={loading}
      />

      <MonthlySummary
        overview={overview}
      />

      <AIOverview
        analysis={analysis}
      />

      <AISuggestions
        analysis={analysis}
      />

      <AIHistory
        history={history}
        removeHistory={removeHistory}
      />

    </div>
  );
}