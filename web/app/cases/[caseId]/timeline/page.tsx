export default function CaseTimelinePage({ params }: { params: { caseId: string } }) {
  return <main>Case {params.caseId} — timeline</main>;
}
