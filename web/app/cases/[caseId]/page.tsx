export default function CasePage({ params }: { params: { caseId: string } }) {
  return <main>Case {params.caseId}</main>;
}
