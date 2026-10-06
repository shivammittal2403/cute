export default function CaseGraphPage({ params }: { params: { caseId: string } }) {
  return <main>Case {params.caseId} — graph</main>;
}
