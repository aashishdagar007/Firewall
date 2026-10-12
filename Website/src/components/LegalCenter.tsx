import { X, FileText, ShieldCheck, Cookie, Scale, LockKeyhole, ServerCog } from 'lucide-react';

export type LegalDocument = 'privacy' | 'terms' | 'cookies' | 'security' | 'acceptable-use' | 'eula' | 'data-processing';

type Props = {
  document: LegalDocument | null;
  onClose: () => void;
};

const documents: Record<LegalDocument, { title: string; icon: typeof FileText; updated: string; sections: { heading: string; body: string }[] }> = {
  privacy: {
    title: 'Privacy Notice', icon: ShieldCheck, updated: '12 October 2026',
    sections: [
      { heading: 'What this notice covers', body: 'This notice explains how ASD Solutions collects and uses information when you visit the AEGIS XII website, request support, or download our software.' },
      { heading: 'Information we collect', body: 'We may collect contact details you provide, technical data needed to secure and operate the site, and download or support-request records. AEGIS XII is designed to operate locally; network telemetry is not sent to us unless you choose to submit it for support.' },
      { heading: 'How we use information', body: 'We use information to provide downloads and support, protect the service, meet legal obligations, and improve the product. We do not sell personal information.' },
      { heading: 'Your choices', body: 'You can manage optional cookies at any time, opt out of product communications, and request access, correction, deletion, or a copy of your personal information by contacting our privacy team.' },
      { heading: 'Retention and transfers', body: 'We retain information only as long as needed for the purposes described here or as required by law. Where information is transferred, we use appropriate safeguards.' },
    ],
  },
  terms: {
    title: 'Terms of Service', icon: Scale, updated: '12 October 2026',
    sections: [
      { heading: 'Agreement', body: 'By accessing this site or downloading AEGIS XII, you agree to these terms and the applicable licence agreement. If you do not agree, do not use the site or software.' },
      { heading: 'Permitted use', body: 'Use the website lawfully and do not interfere with its operation, attempt unauthorised access, or use content except as these terms allow.' },
      { heading: 'Downloads and updates', body: 'You are responsible for verifying that a download is appropriate for your environment and for maintaining secure backups and change-control procedures.' },
      { heading: 'Disclaimers', body: 'The service is provided on an “as available” basis. Security software reduces risk but cannot guarantee prevention of every incident.' },
    ],
  },
  cookies: {
    title: 'Cookie Notice', icon: Cookie, updated: '12 October 2026',
    sections: [
      { heading: 'How cookies are used', body: 'We use essential storage to remember security and consent choices. Optional analytics or preference technologies are used only with your permission.' },
      { heading: 'Managing choices', body: 'Select Cookie preferences in the site footer to accept, reject, or customise optional cookies. You can also clear browser storage at any time.' },
      { heading: 'Cookie categories', body: 'Essential cookies support site operation and cannot be disabled. Preference cookies remember choices. Analytics cookies help us understand aggregated site use.' },
    ],
  },
  security: {
    title: 'Security & Vulnerability Disclosure', icon: LockKeyhole, updated: '12 October 2026',
    sections: [
      { heading: 'Our commitment', body: 'We apply secure development, access control, dependency review, and release validation practices to AEGIS XII and its web services.' },
      { heading: 'Report a vulnerability', body: 'Please report suspected vulnerabilities privately with clear reproduction steps and avoid accessing, changing, or exposing other people’s data. We will acknowledge valid reports and work toward a fix.' },
      { heading: 'Safe harbour', body: 'Good-faith research conducted within this policy will not be pursued by us, provided it avoids privacy harm, service disruption, and unlawful activity.' },
    ],
  },
  'acceptable-use': {
    title: 'Acceptable Use Policy', icon: ServerCog, updated: '12 October 2026',
    sections: [
      { heading: 'Responsible use', body: 'Do not use AEGIS XII to violate law, infringe rights, distribute malware, evade authorised controls, or disrupt systems or networks.' },
      { heading: 'Administrative access', body: 'The product may require elevated permissions. Deploy it only on systems and networks you own or are explicitly authorised to administer.' },
      { heading: 'Enforcement', body: 'We may suspend access to downloads or support where use presents a security, legal, or operational risk.' },
    ],
  },
  eula: {
    title: 'End User Licence Agreement', icon: FileText, updated: '12 October 2026',
    sections: [
      { heading: 'Licence grant', body: 'Subject to these terms, ASD Solutions grants you a limited, non-exclusive, non-transferable licence to install and use AEGIS XII for your authorised internal use.' },
      { heading: 'Restrictions', body: 'You may not reverse engineer, redistribute, rent, sublicense, or remove proprietary notices except where applicable law expressly permits it.' },
      { heading: 'Updates and support', body: 'Updates may modify or retire features. Support commitments, if any, are governed by the plan or agreement under which the software was obtained.' },
      { heading: 'Liability', body: 'To the maximum extent permitted by law, liability is limited as set out in the agreement governing your use. Nothing excludes liability that cannot legally be excluded.' },
    ],
  },
  'data-processing': {
    title: 'Data Processing Addendum', icon: ShieldCheck, updated: '12 October 2026',
    sections: [
      { heading: 'Roles', body: 'Where ASD Solutions processes personal data on behalf of an organisation, that organisation is the controller and ASD Solutions acts as processor for the documented services.' },
      { heading: 'Processing commitments', body: 'We process personal data only on documented instructions, maintain confidentiality, apply appropriate technical and organisational measures, and assist with lawful data-subject requests.' },
      { heading: 'Subprocessors and transfers', body: 'We engage subprocessors only where appropriate safeguards apply and manage international transfers through recognised legal mechanisms when required.' },
    ],
  },
};

export default function LegalCenter({ document, onClose }: Props) {
  if (!document) return null;
  const policy = documents[document];
  const Icon = policy.icon;
  return (
    <div className="fixed inset-0 z-[100] flex items-end sm:items-center justify-center p-0 sm:p-6" role="dialog" aria-modal="true" aria-labelledby="legal-title">
      <button className="absolute inset-0 bg-[#020408]/80 backdrop-blur-sm" aria-label="Close policy" onClick={onClose} />
      <article className="relative w-full max-w-3xl max-h-[88vh] overflow-y-auto rounded-t-3xl sm:rounded-3xl border border-white/10 bg-[#0a0f18] shadow-2xl">
        <header className="sticky top-0 z-10 flex items-center justify-between border-b border-white/10 bg-[#0a0f18]/95 px-6 py-5 backdrop-blur">
          <div className="flex items-center gap-3"><div className="rounded-xl border border-cyan-300/20 bg-cyan-300/10 p-2 text-[#00e5ff]"><Icon className="h-5 w-5" /></div><div><p className="text-[10px] font-bold uppercase tracking-[.2em] text-[#00e5ff]">Legal centre</p><h2 id="legal-title" className="text-xl font-bold text-white">{policy.title}</h2></div></div>
          <button onClick={onClose} className="rounded-lg p-2 text-[#8b9bb4] hover:bg-white/5 hover:text-white" aria-label="Close"><X className="h-5 w-5" /></button>
        </header>
        <div className="px-6 py-7 sm:px-10"><p className="mb-8 text-sm text-[#8b9bb4]">Last updated: {policy.updated}</p><div className="space-y-7">{policy.sections.map((section) => <section key={section.heading}><h3 className="mb-2 text-base font-bold text-white">{section.heading}</h3><p className="text-sm leading-7 text-[#b5c0d2]">{section.body}</p></section>)}</div><p className="mt-10 rounded-xl border border-amber-300/15 bg-amber-300/5 p-4 text-xs leading-5 text-[#c8b98c]">This website policy framework should be reviewed and approved by your legal and privacy teams before production use.</p></div>
      </article>
    </div>
  );
}
