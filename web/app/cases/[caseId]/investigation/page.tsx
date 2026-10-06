export default function CaseInvestigationPage({ params }: { params: { caseId: string } }) {
  return <main>Case {params.caseId} — investigation</main>;
}
