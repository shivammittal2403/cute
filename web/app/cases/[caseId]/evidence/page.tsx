export default function CaseEvidencePage({ params }: { params: { caseId: string } }) {
  return <main>Case {params.caseId} — evidence</main>;
}
