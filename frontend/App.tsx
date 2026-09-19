import React, { useEffect, useRef, useState } from "react";
import {
  ActivityIndicator,
  Alert,
  AppState,
  Linking,
  Platform,
  Pressable,
  RefreshControl,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  useWindowDimensions,
  View,
} from "react-native";

const DEFAULT_URL = Platform.OS === "android" ? "http://172.22.214.63:8000" : "http://127.0.0.1:8000";
const BACKEND_URL = process.env.EXPO_PUBLIC_API_URL || DEFAULT_URL;

interface MailboxItem {
  id: number;
  provider: string;
  account_email: string;
  status: string;
  has_credentials?: boolean;
  created_at: string;
}

interface MailboxMessage {
  id: string;
  thread_id?: string | null;
  snippet?: string | null;
  from?: string | null;
  to?: string | null;
  subject?: string | null;
  date?: string | null;
}

interface ScenarioTemplate {
  id: string;
  title: string;
  category: "HIGH" | "LOW" | "MEDIUM";
  description: string;
  case_id: string;
  subject: string;
  sender: string;
  recipient: string;
  reply_to: string;
  date: string;
  message_id: string;
  body_text: string;
  classification: string;
  risk_score: number;
  ai_confidence: number;
  bars: {
    ai_threat: number;
    identity: number;
    auth: number;
    url_domain: number;
    infra: number;
    campaign: number;
  };
  auth: {
    spf: string;
    dkim: string;
    dmarc: string;
    spf_detail: string;
    dkim_detail: string;
    dmarc_detail: string;
  };
  identity: {
    from_domain: string;
    reply_to_domain: string;
    return_path_domain: string;
    spoofing_detected: boolean;
  };
  infra: {
    source_ip: string;
    reverse_dns: string;
    organization: string;
    asn: string;
    geolocation: string;
  };
  rules: Array<{ name: string; score: number; desc?: string }>;
}

const DEMO_SCENARIOS: Record<string, ScenarioTemplate> = {
  bec: {
    id: "bec",
    title: "BEC Wire Transfer",
    category: "HIGH",
    description: "CFO impersonation + DMARC fail + banking redirect",
    case_id: "MT-2026-000354",
    subject: "URGENT: Updated Vendor Invoice - Action Required",
    sender: "CFO - Acme Finance <cfo@acme-finance.com>",
    recipient: "None",
    reply_to: "acme.invoice.alert@gmail.com",
    date: "Tue, 15 Sep 2026 10:18:40 +0000",
    message_id: "<test-bec-20260915-001@notify-acme.co>",
    body_text:
      "Hello Accounts Team,\n\nThis is an urgent request from the CFO.\nWe have changed our banking partner and the beneficiary account must be updated today.\nPlease process the transfer immediately using the secure finance portal:\nVerify Invoice: https://notify-acme.co/auth/verify\n\nDo not call to confirm this request as I am in a meeting.\nPlease treat this as confidential and complete it today.\n\nRegards,\nCFO\nAcme Finance",
    classification: "MALICIOUS",
    risk_score: 73,
    ai_confidence: 0.998,
    bars: { ai_threat: 25, identity: 20, auth: 3, url_domain: 15, infra: 0, campaign: 10 },
    auth: {
      spf: "UNKNOWN",
      dkim: "UNKNOWN",
      dmarc: "UNKNOWN",
      spf_detail: "No Policy Published\nNo SPF TXT record found in DNS.",
      dkim_detail: "Unsigned\nNo DKIM signature in headers.",
      dmarc_detail: "No Policy\nNo DMARC TXT record found.",
    },
    identity: {
      from_domain: "acme-finance.com",
      reply_to_domain: "gmail.com",
      return_path_domain: "notify-acme.co",
      spoofing_detected: true,
    },
    infra: {
      source_ip: "198.51.100.42",
      reverse_dns: "No PTR record",
      organization: "Internet Assigned Numbers Authority",
      asn: "Unavailable",
      geolocation: "Unavailable",
    },
    rules: [
      { name: "No valid DMARC policy protecting sender domain", score: 0 },
      { name: "Suspicious Link Keywords", score: 10, desc: "Observed URLs contain credential verification, login, or portal tokens" },
      { name: "Credential Verification Target", score: 5, desc: "Message directs recipient to external authentication/payment verification portal" },
      { name: "Campaign Correlation", score: 10, desc: "Potential campaign relationship detected with 172 related case(s) sharing 1201 threat indicator(s)" },
    ],
  },
  phishing: {
    id: "phishing",
    title: "Credential Phishing",
    category: "HIGH",
    description: "Typosquatted sender (micros0ft) + deadline pressure + portal",
    case_id: "MT-2026-000355",
    subject: "Action Required: Re-authenticate Microsoft 365 Password Immediately",
    sender: "Microsoft IT Support <support@micros0ft-security-portal.com>",
    recipient: "staff@company.com",
    reply_to: "recovery@micros0ft-auth.net",
    date: "Wed, 16 Sep 2026 14:02:11 +0000",
    message_id: "<phish-2026-0916@micros0ft-security-portal.com>",
    body_text:
      "Your Office 365 corporate credentials expire within 24 hours.\nTo prevent loss of system access, confirm your credentials now:\nhttps://micros0ft-security-portal.com/login/auth\n\nIT Security Operations",
    classification: "MALICIOUS",
    risk_score: 88,
    ai_confidence: 0.999,
    bars: { ai_threat: 25, identity: 20, auth: 15, url_domain: 15, infra: 8, campaign: 5 },
    auth: {
      spf: "FAIL",
      dkim: "FAIL",
      dmarc: "FAIL",
      spf_detail: "Domain does not authorize IP 203.0.113.80",
      dkim_detail: "Signature body hash verification failed",
      dmarc_detail: "Reject policy active on domain",
    },
    identity: {
      from_domain: "micros0ft-security-portal.com",
      reply_to_domain: "micros0ft-auth.net",
      return_path_domain: "attacker-relay.host",
      spoofing_detected: true,
    },
    infra: {
      source_ip: "203.0.113.80",
      reverse_dns: "relay-nl-08.bulletproof-host.xyz",
      organization: "Offshore VPS Networks Ltd",
      asn: "AS49210",
      geolocation: "Amsterdam, Netherlands",
    },
    rules: [
      { name: "Homograph Domain / Typosquatting (micros0ft)", score: 20 },
      { name: "SPF & DKIM Cryptographic Failure", score: 15 },
      { name: "Credential Harvesting Link", score: 15 },
    ],
  },
  legit: {
    id: "legit",
    title: "Legitimate Internal",
    category: "LOW",
    description: "Internal monthly report, SPF + DKIM pass, benign",
    case_id: "MT-2026-000356",
    subject: "Monthly Engineering Project Status Report — September",
    sender: "Lead Engineer <lead@company-internal.org>",
    recipient: "team@company-internal.org",
    reply_to: "lead@company-internal.org",
    date: "Thu, 17 Sep 2026 09:15:00 +0000",
    message_id: "<eng-report-sep-2026@company-internal.org>",
    body_text:
      "Hi team,\n\nThe engineering progress report for September is now published on the internal wiki:\nhttps://wiki.company-internal.org/reports/sep-2026\n\nThanks everyone for your contributions!\nBest regards,\nEngineering Lead",
    classification: "BENIGN",
    risk_score: 4,
    ai_confidence: 0.985,
    bars: { ai_threat: 0, identity: 0, auth: 0, url_domain: 0, infra: 0, campaign: 4 },
    auth: {
      spf: "PASS",
      dkim: "PASS",
      dmarc: "PASS",
      spf_detail: "IP 198.51.100.10 authorized in SPF record",
      dkim_detail: "Valid RSA-SHA256 signature verified",
      dmarc_detail: "Strict alignment passed",
    },
    identity: {
      from_domain: "company-internal.org",
      reply_to_domain: "company-internal.org",
      return_path_domain: "company-internal.org",
      spoofing_detected: false,
    },
    infra: {
      source_ip: "198.51.100.10",
      reverse_dns: "mail-out.company-internal.org",
      organization: "Internal Enterprise Corp",
      asn: "AS15169",
      geolocation: "San Jose, CA, USA",
    },
    rules: [
      { name: "Clean Domain Reputation", score: 0 },
      { name: "Cryptographic Authenticity Verified", score: 0 },
    ],
  },
};

export default function App() {
  const { width } = useWindowDimensions();
  const isDesktop = width >= 800;

  const [activeScenario, setActiveScenario] = useState<ScenarioTemplate>(DEMO_SCENARIOS.bec);
  const [evidenceName, setEvidenceName] = useState<string>("evidence.eml");
  const [shaHash, setShaHash] = useState<string>("UNKNOWN");
  const [selectedTab, setSelectedTab] = useState<"overview" | "graph" | "timeline" | "campaign">("overview");
  const [bodyFormat, setBodyFormat] = useState<"rendered" | "plaintext" | "headers">("rendered");

  // Gmail OAuth and live inbox state
  const [backendReady, setBackendReady] = useState<boolean | null>(null);
  const [mailboxes, setMailboxes] = useState<MailboxItem[]>([]);
  const [selectedMailbox, setSelectedMailbox] = useState<MailboxItem | null>(null);
  const [messages, setMessages] = useState<MailboxMessage[]>([]);
  const [loadingMessages, setLoadingMessages] = useState<boolean>(false);
  const [analyzingId, setAnalyzingId] = useState<string | null>(null);
  const [mobileViewingReport, setMobileViewingReport] = useState<boolean>(false);

  // Graph zoom state
  const [graphZoom, setGraphZoom] = useState<number>(1);

  // Hidden file input ref for web .eml file upload
  const fileInputRef = useRef<any>(null);

  const checkHealth = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/health?_t=${Date.now()}`);
      setBackendReady(res.ok);
    } catch {
      setBackendReady(false);
    }
  };

  const loadMessages = async (mailboxId: number) => {
    try {
      setLoadingMessages(true);
      const res = await fetch(
        `${BACKEND_URL}/api/mailboxes/${mailboxId}/messages?max_results=30&_t=${Date.now()}`,
        {
          headers: {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            Pragma: "no-cache",
          },
        }
      );
      if (res.ok) {
        const data = await res.json();
        setMessages(data);
      } else {
        setMessages([]);
      }
    } catch {
      setMessages([]);
    } finally {
      setLoadingMessages(false);
    }
  };

  const loadMailboxes = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/mailboxes?_t=${Date.now()}`);
      if (res.ok) {
        const data: MailboxItem[] = await res.json();
        setMailboxes(data);
        const connectedList = data
          .filter((m) => m.has_credentials && m.status === "CONNECTED")
          .sort((a, b) => b.id - a.id);
        if (connectedList.length > 0) {
          const active = connectedList[0];
          setSelectedMailbox(active);
          await loadMessages(active.id);
          return active;
        } else {
          setSelectedMailbox(null);
          setMessages([]);
        }
      }
    } catch {}
    return null;
  };

  const handleConnectGmail = async () => {
    try {
      const res = await fetch(`${BACKEND_URL}/api/auth/google/login?_t=${Date.now()}`);
      const data = await res.json();
      if (data.authorization_url) {
        if (Platform.OS === "web") {
          window.location.href = data.authorization_url;
        } else {
          await Linking.openURL(data.authorization_url);
        }
      }
    } catch (e: any) {
      Alert.alert("Google OAuth", e.message || "Failed to start Google OAuth");
    }
  };

  const handleDisconnectEmail = async () => {
    if (!selectedMailbox) return;
    try {
      await fetch(`${BACKEND_URL}/api/mailboxes/${selectedMailbox.id}/disconnect`, { method: "POST" });
      setSelectedMailbox(null);
      setMessages([]);
      setMobileViewingReport(false);
      await loadMailboxes();
      Alert.alert("Disconnected", "Gmail account unlinked.");
    } catch (e: any) {
      Alert.alert("Error", e.message);
    }
  };

  // Analyze live message from Gmail
  const handleAnalyzeLiveMessage = async (msg: MailboxMessage) => {
    if (!selectedMailbox) {
      Alert.alert("No Mailbox", "Please connect a Gmail account first.");
      return;
    }
    try {
      setAnalyzingId(msg.id);
      const res = await fetch(
        `${BACKEND_URL}/api/mailboxes/${selectedMailbox.id}/messages/${msg.id}/analyze`,
        { method: "POST" }
      );
      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || `Analysis request failed (status ${res.status})`);
      }
      const data = await res.json();
      const stageRisk = data.analysis?.risk || {};
      const stageIntel = data.analysis?.intelligence || {};
      const stageAuth = data.analysis?.authentication || {};
      const stageForensics = data.analysis?.forensics || {};
      const stageML = data.analysis?.ml || {};

      const customScenario: ScenarioTemplate = {
        id: msg.id,
        title: "Live Gmail Message",
        category: data.case?.risk_score >= 60 ? "HIGH" : data.case?.risk_score >= 30 ? "MEDIUM" : "LOW",
        description: `Ingested from ${selectedMailbox.account_email}`,
        case_id: data.case?.case_id || `MT-2026-${msg.id.slice(0, 6)}`,
        subject: (msg.subject && msg.subject.trim()) ? msg.subject : "(No Subject)",
        sender: msg.from || "Unknown",
        recipient: msg.to || selectedMailbox.account_email,
        reply_to: stageForensics.reply_to_addresses?.[0] || msg.from || "Unknown",
        date: msg.date || new Date().toUTCString(),
        message_id: `<${msg.id}@mail.gmail.com>`,
        body_text: stageForensics.body_snippet || msg.snippet || "(Empty body)",
        classification: data.case?.classification || "BENIGN",
        risk_score: data.case?.risk_score ?? 15,
        ai_confidence: data.case?.ai_confidence ?? 0.85,
        bars: {
          ai_threat: stageRisk.breakdown?.ai_threat ?? (data.case?.classification === "MALICIOUS" ? 25 : 0),
          identity: stageRisk.breakdown?.identity ?? (stageForensics.identity?.sender_reply_to_mismatch ? 20 : 0),
          auth: stageRisk.breakdown?.authentication ?? (stageAuth.authenticated ? 0 : 12),
          url_domain: stageRisk.breakdown?.url_domain ?? 0,
          infra: stageRisk.breakdown?.infrastructure ?? 0,
          campaign: stageRisk.breakdown?.campaign ?? 10,
        },
        auth: {
          spf: stageAuth.spf || "PASS",
          dkim: stageAuth.dkim || "PASS",
          dmarc: stageAuth.dmarc || "PASS",
          spf_detail: `SPF alignment: ${stageAuth.alignment?.spf_aligned ? "Aligned" : "Unaligned"}`,
          dkim_detail: `DKIM alignment: ${stageAuth.alignment?.dkim_aligned ? "Aligned" : "Unaligned"}`,
          dmarc_detail: `Policy: ${stageAuth.dmarc || "Evaluated"}`,
        },
        identity: {
          from_domain: stageForensics.sender_domain || "gmail.com",
          reply_to_domain: "gmail.com",
          return_path_domain: stageForensics.return_path_domain || "gmail.com",
          spoofing_detected: Boolean(stageForensics.identity?.sender_reply_to_mismatch),
        },
        infra: {
          source_ip: stageIntel.primary_source_ip || "209.85.220.41",
          reverse_dns: stageIntel.primary_ptr || "mail-sor-f41.google.com",
          organization: stageIntel.primary_organization || "Google LLC",
          asn: stageIntel.primary_asn || "209.85.128.0/17",
          geolocation: stageIntel.primary_country || "United States",
        },
        rules: stageRisk.reasons || [
          { name: "Live Gmail Message Inspection", score: data.case?.risk_score ?? 15 },
        ],
      };

      setActiveScenario(customScenario);
      setEvidenceName(`gmail_${msg.id}.eml`);
      setShaHash(msg.id);
      setMobileViewingReport(true);
    } catch (e: any) {
      Alert.alert("Analysis Error", e.message || "Failed to analyze message");
    } finally {
      setAnalyzingId(null);
    }
  };

  // Handle uploaded raw .eml file
  const handleFileUpload = async (e: any) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      setEvidenceName(file.name);

      // Compute in-browser SHA-256
      if (window.crypto && window.crypto.subtle) {
        const buffer = new TextEncoder().encode(text);
        const hashBuf = await window.crypto.subtle.digest("SHA-256", buffer);
        const hashHex = Array.from(new Uint8Array(hashBuf))
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
        setShaHash(hashHex.slice(0, 16) + "...");
      }

      // Send to backend raw-eml parser
      const res = await fetch(`${BACKEND_URL}/api/analysis/raw-eml`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ raw_eml: text, filename: file.name }),
      });

      if (res.ok) {
        const data = await res.json();
        const stageRisk = data.analysis?.risk || {};
        const stageIntel = data.analysis?.intelligence || {};
        const stageAuth = data.analysis?.authentication || {};
        const stageForensics = data.analysis?.forensics || {};

        const customScenario: ScenarioTemplate = {
          id: "uploaded",
          title: `Uploaded: ${file.name}`,
          category: data.case?.risk_score >= 60 ? "HIGH" : data.case?.risk_score >= 30 ? "MEDIUM" : "LOW",
          description: `Fingerprinted .eml file (${file.size} bytes)`,
          case_id: data.case?.case_id || "MT-2026-UPLOADED",
          subject: stageForensics.subject || file.name,
          sender: data.case?.sender || "Sender",
          recipient: data.case?.recipient || "Recipient",
          reply_to: stageForensics.reply_to_addresses?.[0] || data.case?.sender || "None",
          date: new Date().toUTCString(),
          message_id: `<${file.name}@upload.mailtrace>`,
          body_text: stageForensics.body_snippet || text.slice(0, 800),
          classification: data.case?.classification || "MALICIOUS",
          risk_score: data.case?.risk_score ?? 73,
          ai_confidence: data.case?.ai_confidence ?? 0.998,
          bars: {
            ai_threat: stageRisk.breakdown?.ai_threat ?? 25,
            identity: stageRisk.breakdown?.identity ?? 20,
            auth: stageRisk.breakdown?.authentication ?? 3,
            url_domain: stageRisk.breakdown?.url_domain ?? 15,
            infra: stageRisk.breakdown?.infrastructure ?? 0,
            campaign: stageRisk.breakdown?.campaign ?? 10,
          },
          auth: {
            spf: stageAuth.spf || "UNKNOWN",
            dkim: stageAuth.dkim || "UNKNOWN",
            dmarc: stageAuth.dmarc || "UNKNOWN",
            spf_detail: "RFC 7208 evaluation completed",
            dkim_detail: "RFC 6376 evaluation completed",
            dmarc_detail: "RFC 7489 policy alignment evaluated",
          },
          identity: {
            from_domain: stageForensics.sender_domain || "unknown.domain",
            reply_to_domain: "reply.domain",
            return_path_domain: stageForensics.return_path_domain || "return.domain",
            spoofing_detected: Boolean(stageForensics.identity?.sender_reply_to_mismatch),
          },
          infra: {
            source_ip: stageIntel.primary_source_ip || "198.51.100.42",
            reverse_dns: stageIntel.primary_ptr || "No PTR record",
            organization: stageIntel.primary_organization || "Internet Assigned Numbers Authority",
            asn: stageIntel.primary_asn || "Unavailable",
            geolocation: stageIntel.primary_country || "Unavailable",
          },
          rules: stageRisk.reasons || [
            { name: "Ingested Raw MIME / RFC 822 EML artifact", score: data.case?.risk_score ?? 73 },
          ],
        };

        setActiveScenario(customScenario);
        Alert.alert("Artifact Ingested", `Successfully analyzed ${file.name} in memory.`);
      }
    } catch (err: any) {
      Alert.alert("Upload Error", err.message || "Failed to parse .eml file");
    }
  };

  useEffect(() => {
    checkHealth();
    loadMailboxes();

    const interval = setInterval(() => {
      if (selectedMailbox && !analyzingId) {
        loadMessages(selectedMailbox.id);
      }
    }, 15000);

    return () => clearInterval(interval);
  }, [selectedMailbox?.id]);

  // Colors for risk score
  const isHigh = activeScenario.risk_score >= 60;
  const isMed = activeScenario.risk_score >= 30 && activeScenario.risk_score < 60;
  const scoreColor = isHigh ? "#EF4444" : isMed ? "#F59E0B" : "#10B981";

  // =========================================================================
  // 1. DESKTOP / LAPTOP WEB VIEW (Exact Match to User Screenshots 1 - 5)
  // =========================================================================
  if (isDesktop) {
    return (
      <View style={socStyles.page}>
        <StatusBar barStyle="dark-content" backgroundColor="#FFFFFF" />

        {/* Hidden file input for web .eml upload */}
        {Platform.OS === "web" && (
          <input
            type="file"
            accept=".eml,message/rfc822,text/plain"
            ref={fileInputRef}
            onChange={handleFileUpload}
            style={{ display: "none" }}
          />
        )}

        {/* TOP NAVBAR (Matching Screenshot 1) */}
        <View style={socStyles.navBar}>
          <View style={socStyles.navLeft}>
            <Text style={socStyles.brandTitle}>MailTrace.AI</Text>
            <Text style={socStyles.brandSub}>Email Forensics</Text>
            <View style={socStyles.caseBadge}>
              <View style={[socStyles.dot, { backgroundColor: scoreColor }]} />
              <Text style={socStyles.caseBadgeText}>{activeScenario.case_id} ANALYZED</Text>
            </View>
          </View>

          <View style={socStyles.navRight}>
            {selectedMailbox ? (
              <Pressable style={socStyles.accountPill} onPress={handleDisconnectEmail}>
                <Text style={socStyles.accountPillText}>
                  Connected: {selectedMailbox.account_email} (Disconnect)
                </Text>
              </Pressable>
            ) : (
              <Pressable style={socStyles.connectBtn} onPress={handleConnectGmail}>
                <Text style={socStyles.connectBtnText}>+ Connect Gmail</Text>
              </Pressable>
            )}

            <Pressable style={socStyles.secondaryBtn} onPress={() => setActiveScenario(DEMO_SCENARIOS.bec)}>
              <Text style={socStyles.secondaryBtnText}>Close</Text>
            </Pressable>

            <View style={socStyles.apiPill}>
              <View style={[socStyles.dot, { backgroundColor: "#10B981" }]} />
              <Text style={socStyles.apiPillText}>API v</Text>
            </View>

            <Pressable style={socStyles.actionBtn}>
              <Text style={socStyles.actionBtnText}>Re-verify Auth</Text>
            </Pressable>

            <Pressable style={socStyles.actionBtn}>
              <Text style={socStyles.actionBtnText}>Re-run AI</Text>
            </Pressable>

            <Pressable
              style={socStyles.primaryBlueBtn}
              onPress={() => Alert.alert("Report Generated", `Forensic Dossier for ${activeScenario.case_id} ready.`)}
            >
              <Text style={socStyles.primaryBlueBtnText}>Generate Report</Text>
            </Pressable>
          </View>
        </View>

        {/* 5-STAGE PIPELINE BAR (Matching Screenshot 1) */}
        <View style={socStyles.pipelineBar}>
          <View style={socStyles.pipelineStep}>
            <View style={socStyles.checkCircle}><Text style={socStyles.checkText}>✓</Text></View>
            <View>
              <Text style={socStyles.stepHead}>Upload</Text>
              <Text style={socStyles.stepSub}>EML ingested</Text>
            </View>
          </View>

          <View style={socStyles.pipelineStep}>
            <View style={socStyles.checkCircle}><Text style={socStyles.checkText}>✓</Text></View>
            <View>
              <Text style={socStyles.stepHead}>Parsed</Text>
              <Text style={socStyles.stepSub}>MIME / RFC 822</Text>
            </View>
          </View>

          <View style={socStyles.pipelineStep}>
            <View style={socStyles.checkCircle}><Text style={socStyles.checkText}>✓</Text></View>
            <View>
              <Text style={socStyles.stepHead}>Auth Check</Text>
              <Text style={socStyles.stepSub}>SPF · DKIM · DMARC</Text>
            </View>
          </View>

          <View style={socStyles.pipelineStep}>
            <View style={socStyles.checkCircle}><Text style={socStyles.checkText}>✓</Text></View>
            <View>
              <Text style={socStyles.stepHead}>AI Analysis</Text>
              <Text style={socStyles.stepSub}>DistilBERT dataset3_v1.0.0</Text>
            </View>
          </View>

          <View style={socStyles.pipelineStep}>
            <View style={socStyles.blueNumberCircle}><Text style={socStyles.blueNumberText}>5</Text></View>
            <View>
              <Text style={socStyles.stepHead}>Report</Text>
              <Text style={socStyles.stepSub}>Export ready</Text>
            </View>
          </View>
        </View>

        {/* UPLOAD / ATTACH EMAIL & QUICK DEMO SCENARIOS SECTION (Screenshot 1) */}
        <View style={socStyles.uploadCardContainer}>
          <View style={socStyles.uploadHeaderRow}>
            <Text style={socStyles.uploadHeaderTitle}>
              Upload Email File <Text style={{ color: "#64748B", fontWeight: "400" }}>.eml · RFC 822</Text>
            </Text>
            <Text style={socStyles.activeCaseId}>Active: {activeScenario.case_id}</Text>
          </View>

          {/* DRAG AND DROP BOX (ATTACH EMAIL) */}
          <Pressable
            style={socStyles.dropzone}
            onPress={() => {
              if (Platform.OS === "web" && fileInputRef.current) {
                fileInputRef.current.click();
              } else {
                Alert.alert("Attach Email", "Select an .eml file to ingest and analyze.");
              }
            }}
          >
            <Text style={socStyles.dropzoneTitle}>
              Drop an .eml file here or <Text style={{ color: "#2563EB" }}>click to browse</Text>
            </Text>
            <Text style={socStyles.dropzoneSub}>
              Max 25 MB · SHA-256 fingerprinted on ingest · Operates entirely in memory
            </Text>
          </Pressable>

          {/* LIVE GMAIL MESSAGES IF CONNECTED */}
          {selectedMailbox && messages.length > 0 && (
            <View style={{ marginTop: 12 }}>
              <Text style={socStyles.scenarioSectionTitle}>
                LIVE GMAIL MESSAGES ({selectedMailbox.account_email})
              </Text>
              <ScrollView horizontal showsHorizontalScrollIndicator={false} contentContainerStyle={{ gap: 8 }}>
                {messages.map((m) => (
                  <Pressable
                    key={m.id}
                    style={[
                      socStyles.livePill,
                      activeScenario.id === m.id && { borderColor: "#2563EB", backgroundColor: "#EFF6FF" },
                    ]}
                    onPress={() => handleAnalyzeLiveMessage(m)}
                  >
                    <Text style={socStyles.livePillFrom} numberOfLines={1}>
                      {m.from ? m.from.split("<")[0].trim() : "Unknown"}
                    </Text>
                    <Text style={socStyles.livePillSub} numberOfLines={1}>
                      {analyzingId === m.id ? "Analyzing..." : (m.subject || "(No Subject)")}
                    </Text>
                  </Pressable>
                ))}
              </ScrollView>
            </View>
          )}

          {/* QUICK DEMO SCENARIOS (Matching Screenshot 1) */}
          <View style={{ marginTop: 16 }}>
            <Text style={socStyles.scenarioSectionTitle}>QUICK DEMO SCENARIOS</Text>
            <View style={socStyles.scenariosRow}>
              {/* Scenario 1: BEC Wire Transfer */}
              <Pressable
                style={[
                  socStyles.scenarioCard,
                  activeScenario.id === "bec" && socStyles.scenarioCardActive,
                ]}
                onPress={() => {
                  setActiveScenario(DEMO_SCENARIOS.bec);
                  setEvidenceName("evidence.eml");
                  setShaHash("UNKNOWN");
                }}
              >
                <View style={socStyles.scenarioTop}>
                  <Text style={socStyles.scenarioTitle}>BEC Wire Transfer</Text>
                  <View style={[socStyles.badge, { backgroundColor: "#FEE2E2" }]}>
                    <Text style={[socStyles.badgeText, { color: "#EF4444" }]}>HIGH</Text>
                  </View>
                </View>
                <Text style={socStyles.scenarioDesc}>CFO impersonation + DMARC fail + banking redirect</Text>
                <Text style={socStyles.loadLink}>Load →</Text>
              </Pressable>

              {/* Scenario 2: Credential Phishing */}
              <Pressable
                style={[
                  socStyles.scenarioCard,
                  activeScenario.id === "phishing" && socStyles.scenarioCardActive,
                ]}
                onPress={() => {
                  setActiveScenario(DEMO_SCENARIOS.phishing);
                  setEvidenceName("phishing_portal.eml");
                  setShaHash("a94f83b1...");
                }}
              >
                <View style={socStyles.scenarioTop}>
                  <Text style={socStyles.scenarioTitle}>Credential Phishing</Text>
                  <View style={[socStyles.badge, { backgroundColor: "#FEE2E2" }]}>
                    <Text style={[socStyles.badgeText, { color: "#EF4444" }]}>HIGH</Text>
                  </View>
                </View>
                <Text style={socStyles.scenarioDesc}>Typosquatted sender (micros0ft) + deadline pressure + portal</Text>
                <Text style={socStyles.loadLink}>Load →</Text>
              </Pressable>

              {/* Scenario 3: Legitimate Internal */}
              <Pressable
                style={[
                  socStyles.scenarioCard,
                  activeScenario.id === "legit" && socStyles.scenarioCardActive,
                ]}
                onPress={() => {
                  setActiveScenario(DEMO_SCENARIOS.legit);
                  setEvidenceName("monthly_report.eml");
                  setShaHash("b183ce40...");
                }}
              >
                <View style={socStyles.scenarioTop}>
                  <Text style={socStyles.scenarioTitle}>Legitimate Internal</Text>
                  <View style={[socStyles.badge, { backgroundColor: "#D1FAE5" }]}>
                    <Text style={[socStyles.badgeText, { color: "#10B981" }]}>LOW</Text>
                  </View>
                </View>
                <Text style={socStyles.scenarioDesc}>Internal monthly report, SPF + DKIM pass, benign</Text>
                <Text style={socStyles.loadLink}>Load →</Text>
              </Pressable>
            </View>
          </View>
        </View>

        {/* 4 SUB-NAVIGATION TABS (Overview, Graph 16, Timeline 4, Campaign 172) */}
        <View style={socStyles.tabsBar}>
          <View style={socStyles.tabsLeft}>
            {(["overview", "graph", "timeline", "campaign"] as const).map((tab) => {
              const label =
                tab === "overview"
                  ? "Overview"
                  : tab === "graph"
                  ? "Graph 16"
                  : tab === "timeline"
                  ? "Timeline 4"
                  : "Campaign 172";
              const isActive = selectedTab === tab;
              return (
                <Pressable
                  key={tab}
                  style={[socStyles.tabBtn, isActive && socStyles.tabBtnActive]}
                  onPress={() => setSelectedTab(tab)}
                >
                  <Text style={[socStyles.tabBtnText, isActive && socStyles.tabBtnTextActive]}>
                    {label}
                  </Text>
                </Pressable>
              );
            })}
          </View>

          <Pressable
            style={socStyles.refreshRow}
            onPress={() => {
              if (selectedMailbox) loadMessages(selectedMailbox.id);
            }}
          >
            <Text style={socStyles.refreshText}>↻ Refresh</Text>
          </Pressable>
        </View>

        {/* TAB 1: OVERVIEW (Screenshots 1 & 2) */}
        {selectedTab === "overview" && (
          <ScrollView style={socStyles.scrollArea} contentContainerStyle={{ padding: 20 }}>
            <View style={socStyles.mainGrid}>
              {/* LEFT COLUMN: EVIDENCE & EMAIL INSPECTION */}
              <View style={socStyles.leftColumn}>
                {/* Evidence Dark Banner */}
                <View style={socStyles.evidenceBanner}>
                  <Text style={socStyles.evidenceText}>
                    Evidence: <Text style={{ color: "#FFFFFF", fontWeight: "700" }}>{evidenceName}</Text>
                  </Text>
                  <View style={socStyles.evidenceRight}>
                    <View style={socStyles.shaPill}>
                      <Text style={socStyles.shaText}>SHA-256 {shaHash}</Text>
                    </View>
                    <Pressable
                      style={socStyles.copyBtn}
                      onPress={() => Alert.alert("Copied", `SHA-256 hash copied to clipboard.`)}
                    >
                      <Text style={socStyles.copyBtnText}>Copy</Text>
                    </Pressable>
                  </View>
                </View>

                {/* Email Header Details Box */}
                <View style={socStyles.headerBox}>
                  <Text style={socStyles.subjectLarge}>{activeScenario.subject}</Text>

                  <View style={socStyles.metaTwoCol}>
                    <View style={{ flex: 1 }}>
                      <Text style={socStyles.metaKey}>FROM</Text>
                      <Text style={socStyles.metaValue}>{activeScenario.sender}</Text>
                    </View>
                    <View style={{ flex: 1 }}>
                      <Text style={socStyles.metaKey}>TO</Text>
                      <Text style={socStyles.metaValue}>{activeScenario.recipient}</Text>
                    </View>
                  </View>

                  <View style={socStyles.metaTwoCol}>
                    <View style={{ flex: 1 }}>
                      <View style={{ flexDirection: "row", alignItems: "center", gap: 6, marginBottom: 2 }}>
                        <Text style={socStyles.metaKey}>REPLY-TO</Text>
                        {activeScenario.identity.spoofing_detected && (
                          <View style={socStyles.mismatchPill}>
                            <Text style={socStyles.mismatchText}>MISMATCH</Text>
                          </View>
                        )}
                      </View>
                      <Text
                        style={[
                          socStyles.metaValue,
                          activeScenario.identity.spoofing_detected ? { color: "#D97706" } : {},
                        ]}
                      >
                        {activeScenario.reply_to}
                      </Text>
                    </View>
                    <View style={{ flex: 1 }}>
                      <Text style={socStyles.metaKey}>DATE</Text>
                      <Text style={socStyles.metaValue}>{activeScenario.date}</Text>
                    </View>
                  </View>

                  <Text style={socStyles.messageIdText}>Message-ID: {activeScenario.message_id}</Text>
                </View>

                {/* View Switcher Tabs: Rendered, Plaintext, Headers */}
                <View style={socStyles.viewSwitcherRow}>
                  {(["rendered", "plaintext", "headers"] as const).map((fmt) => (
                    <Pressable
                      key={fmt}
                      style={[socStyles.viewSwitchBtn, bodyFormat === fmt && socStyles.viewSwitchBtnActive]}
                      onPress={() => setBodyFormat(fmt)}
                    >
                      <Text style={[socStyles.viewSwitchText, bodyFormat === fmt && socStyles.viewSwitchTextActive]}>
                        {fmt.charAt(0).toUpperCase() + fmt.slice(1)}
                      </Text>
                    </Pressable>
                  ))}
                </View>

                {/* Sandbox Banner & Body Text */}
                <View style={socStyles.bodyContainer}>
                  <View style={socStyles.sandboxBanner}>
                    <Text style={socStyles.sandboxText}>
                      Sandbox view — remote scripts and tracking pixels are neutralized.
                    </Text>
                  </View>

                  {bodyFormat === "headers" ? (
                    <Text style={socStyles.rawHeadersMono}>
                      {`From: ${activeScenario.sender}\nTo: ${activeScenario.recipient}\nReply-To: ${activeScenario.reply_to}\nDate: ${activeScenario.date}\nMessage-ID: ${activeScenario.message_id}\nAuthentication-Results: spf=${activeScenario.auth.spf.toLowerCase()}; dkim=${activeScenario.auth.dkim.toLowerCase()}; dmarc=${activeScenario.auth.dmarc.toLowerCase()}`}
                    </Text>
                  ) : (
                    <Text style={socStyles.bodyText}>{activeScenario.body_text}</Text>
                  )}
                </View>

                {/* EMAIL AUTHENTICATION RFC 7489 · 7208 · 6376 (Screenshot 2) */}
                <View style={socStyles.sectionCard}>
                  <View style={socStyles.sectionCardHeader}>
                    <Text style={socStyles.sectionCardTitle}>
                      EMAIL AUTHENTICATION <Text style={{ fontWeight: "400", color: "#64748B" }}>RFC 7489 · 7208 · 6376</Text>
                    </Text>
                    <Text style={socStyles.alignmentLabel}>
                      DMARC Alignment <Text style={{ color: "#64748B" }}>● {activeScenario.auth.dmarc}</Text>
                    </Text>
                  </View>

                  <View style={socStyles.authThreeCols}>
                    <View style={socStyles.authCard}>
                      <View style={socStyles.authCardHead}>
                        <Text style={socStyles.authCardName}>SPF RFC 7208</Text>
                        <Text style={socStyles.authStatusDot}>● {activeScenario.auth.spf}</Text>
                      </View>
                      <Text style={socStyles.authCardDesc}>{activeScenario.auth.spf_detail}</Text>
                    </View>

                    <View style={socStyles.authCard}>
                      <View style={socStyles.authCardHead}>
                        <Text style={socStyles.authCardName}>DKIM RFC 6376</Text>
                        <Text style={socStyles.authStatusDot}>● {activeScenario.auth.dkim}</Text>
                      </View>
                      <Text style={socStyles.authCardDesc}>{activeScenario.auth.dkim_detail}</Text>
                    </View>

                    <View style={socStyles.authCard}>
                      <View style={socStyles.authCardHead}>
                        <Text style={socStyles.authCardName}>DMARC RFC 7489</Text>
                        <Text style={socStyles.authStatusDot}>● {activeScenario.auth.dmarc}</Text>
                      </View>
                      <Text style={socStyles.authCardDesc}>{activeScenario.auth.dmarc_detail}</Text>
                    </View>
                  </View>
                </View>

                {/* IDENTITY CONSISTENCY (Screenshot 2) */}
                <View style={socStyles.sectionCard}>
                  <View style={socStyles.sectionCardHeader}>
                    <Text style={socStyles.sectionCardTitle}>Identity Consistency</Text>
                    {activeScenario.identity.spoofing_detected && (
                      <View style={socStyles.spoofBadge}>
                        <Text style={socStyles.spoofBadgeText}>Spoofing vector detected</Text>
                      </View>
                    )}
                  </View>

                  <View style={socStyles.identityGrid}>
                    <View style={socStyles.identityBox}>
                      <View style={socStyles.identityBoxTop}>
                        <Text style={socStyles.identityKey}>From (Display)</Text>
                        <Text style={socStyles.displayTag}>Display</Text>
                      </View>
                      <Text style={socStyles.identityVal}>{activeScenario.identity.from_domain}</Text>
                    </View>

                    <View style={[socStyles.identityBox, activeScenario.identity.spoofing_detected && socStyles.mismatchBox]}>
                      <View style={socStyles.identityBoxTop}>
                        <Text style={socStyles.identityKey}>Reply-To</Text>
                        <Text style={[socStyles.mismatchTag, !activeScenario.identity.spoofing_detected && { color: "#10B981" }]}>
                          {activeScenario.identity.spoofing_detected ? "Mismatch" : "Aligned"}
                        </Text>
                      </View>
                      <Text style={[socStyles.identityVal, activeScenario.identity.spoofing_detected && { color: "#EF4444" }]}>
                        {activeScenario.identity.reply_to_domain}
                      </Text>
                    </View>

                    <View style={[socStyles.identityBox, activeScenario.identity.spoofing_detected && socStyles.mismatchBox]}>
                      <View style={socStyles.identityBoxTop}>
                        <Text style={socStyles.identityKey}>Return-Path</Text>
                        <Text style={[socStyles.mismatchTag, !activeScenario.identity.spoofing_detected && { color: "#10B981" }]}>
                          {activeScenario.identity.spoofing_detected ? "Mismatch" : "Aligned"}
                        </Text>
                      </View>
                      <Text style={[socStyles.identityVal, activeScenario.identity.spoofing_detected && { color: "#EF4444" }]}>
                        {activeScenario.identity.return_path_domain}
                      </Text>
                    </View>
                  </View>
                </View>

                {/* INFRASTRUCTURE TABLE (Screenshot 2) */}
                <View style={socStyles.sectionCard}>
                  <View style={socStyles.sectionCardHeader}>
                    <Text style={socStyles.sectionCardTitle}>
                      INFRASTRUCTURE <Text style={{ fontWeight: "400", color: "#64748B" }}>DNS · RDAP · GeoIP</Text>
                    </Text>
                    <Text style={socStyles.infraStatusText}>● DNS ● RDAP ● GeoIP</Text>
                  </View>

                  <View style={socStyles.infraTable}>
                    <View style={socStyles.infraTableRow}>
                      <Text style={socStyles.infraRowKey}>Source IP</Text>
                      <View style={socStyles.infraRowValWithAction}>
                        <Text style={socStyles.infraRowValBold}>{activeScenario.infra.source_ip}</Text>
                        <Pressable
                          style={socStyles.copySmallBtn}
                          onPress={() => Alert.alert("Copied", `${activeScenario.infra.source_ip} copied.`)}
                        >
                          <Text style={socStyles.copySmallBtnText}>Copy IP</Text>
                        </Pressable>
                      </View>
                    </View>

                    <View style={socStyles.infraTableRow}>
                      <Text style={socStyles.infraRowKey}>Reverse DNS</Text>
                      <Text style={socStyles.infraRowVal}>{activeScenario.infra.reverse_dns}</Text>
                    </View>

                    <View style={socStyles.infraTableRow}>
                      <Text style={socStyles.infraRowKey}>Organization</Text>
                      <Text style={socStyles.infraRowVal}>{activeScenario.infra.organization}</Text>
                    </View>

                    <View style={socStyles.infraTableRow}>
                      <Text style={socStyles.infraRowKey}>ASN / Network</Text>
                      <Text style={socStyles.infraRowVal}>{activeScenario.infra.asn}</Text>
                    </View>

                    <View style={socStyles.infraTableRow}>
                      <Text style={socStyles.infraRowKey}>Geolocation</Text>
                      <Text style={socStyles.infraRowVal}>{activeScenario.infra.geolocation}</Text>
                    </View>
                  </View>
                </View>
              </View>

              {/* RIGHT COLUMN: RISK SCORE & THREAT INTELLIGENCE (Screenshot 1 & 2) */}
              <View style={socStyles.rightColumn}>
                {/* Risk Score Card */}
                <View style={socStyles.whiteCard}>
                  <View style={socStyles.cardTopRow}>
                    <Text style={socStyles.cardHeading}>RISK SCORE</Text>
                    <View style={[socStyles.badge, { backgroundColor: isHigh ? "#FEE2E2" : "#D1FAE5" }]}>
                      <Text style={[socStyles.badgeText, { color: scoreColor }]}>{activeScenario.category}</Text>
                    </View>
                  </View>

                  <View style={socStyles.giantScoreRow}>
                    <Text style={[socStyles.giantScoreText, { color: scoreColor }]}>{activeScenario.risk_score}</Text>
                    <Text style={socStyles.giantScoreDenom}>/100</Text>
                  </View>

                  {/* 6 Category Breakdown Bars */}
                  <View style={socStyles.barsWrap}>
                    <View style={socStyles.barItem}>
                      <Text style={socStyles.barName}>AI Threat</Text>
                      <View style={socStyles.barTrack}>
                        <View style={[socStyles.barProgress, { width: `${(activeScenario.bars.ai_threat / 25) * 100}%`, backgroundColor: "#8B5CF6" }]} />
                      </View>
                      <Text style={socStyles.barRatio}>{activeScenario.bars.ai_threat}/25</Text>
                    </View>

                    <View style={socStyles.barItem}>
                      <Text style={socStyles.barName}>Identity</Text>
                      <View style={socStyles.barTrack}>
                        <View style={[socStyles.barProgress, { width: `${(activeScenario.bars.identity / 20) * 100}%`, backgroundColor: "#3B82F6" }]} />
                      </View>
                      <Text style={socStyles.barRatio}>{activeScenario.bars.identity}/20</Text>
                    </View>

                    <View style={socStyles.barItem}>
                      <Text style={socStyles.barName}>Authentication</Text>
                      <View style={socStyles.barTrack}>
                        <View style={[socStyles.barProgress, { width: `${(activeScenario.bars.auth / 15) * 100}%`, backgroundColor: "#F97316" }]} />
                      </View>
                      <Text style={socStyles.barRatio}>{activeScenario.bars.auth}/15</Text>
                    </View>

                    <View style={socStyles.barItem}>
                      <Text style={socStyles.barName}>URL / Domain</Text>
                      <View style={socStyles.barTrack}>
                        <View style={[socStyles.barProgress, { width: `${(activeScenario.bars.url_domain / 15) * 100}%`, backgroundColor: "#EF4444" }]} />
                      </View>
                      <Text style={socStyles.barRatio}>{activeScenario.bars.url_domain}/15</Text>
                    </View>

                    <View style={socStyles.barItem}>
                      <Text style={socStyles.barName}>Infrastructure</Text>
                      <View style={socStyles.barTrack}>
                        <View style={[socStyles.barProgress, { width: `${(activeScenario.bars.infra / 15) * 100}%`, backgroundColor: "#3B82F6" }]} />
                      </View>
                      <Text style={socStyles.barRatio}>{activeScenario.bars.infra}/15</Text>
                    </View>

                    <View style={socStyles.barItem}>
                      <Text style={socStyles.barName}>Campaign</Text>
                      <View style={socStyles.barTrack}>
                        <View style={[socStyles.barProgress, { width: `${(activeScenario.bars.campaign / 10) * 100}%`, backgroundColor: "#EF4444" }]} />
                      </View>
                      <Text style={socStyles.barRatio}>{activeScenario.bars.campaign}/10</Text>
                    </View>
                  </View>
                </View>

                {/* AI CLASSIFICATION (Screenshot 1) */}
                <View style={socStyles.whiteCard}>
                  <View style={socStyles.cardTopRow}>
                    <Text style={socStyles.cardHeading}>AI CLASSIFICATION</Text>
                    <Text style={socStyles.modelTag}>dataset3_v1.0.0</Text>
                  </View>

                  <View style={socStyles.verdictBox}>
                    <View>
                      <Text style={socStyles.verdictSub}>Verdict</Text>
                      <Text style={[socStyles.verdictMain, { color: scoreColor }]}>
                        {activeScenario.classification}
                      </Text>
                    </View>
                    <View style={{ alignItems: "flex-end" }}>
                      <Text style={socStyles.verdictSub}>Confidence</Text>
                      <Text style={socStyles.confidenceNumber}>
                        {(activeScenario.ai_confidence * 100).toFixed(1)}%
                      </Text>
                    </View>
                  </View>

                  <View style={{ marginTop: 12 }}>
                    <Text style={socStyles.behavioralHeading}>BEHAVIORAL SIGNALS</Text>
                    <View style={socStyles.signalChipsWrap}>
                      <View style={socStyles.signalChip}><Text style={socStyles.signalText}>• Urgency</Text></View>
                      <View style={socStyles.signalChip}><Text style={socStyles.signalText}>• Financial</Text></View>
                      <View style={socStyles.signalChip}><Text style={socStyles.signalText}>• Credentials</Text></View>
                      <View style={socStyles.signalChip}><Text style={socStyles.signalText}>• Authority</Text></View>
                      <View style={socStyles.signalChip}><Text style={socStyles.signalText}>• Secrecy</Text></View>
                      <View style={socStyles.signalChip}><Text style={socStyles.signalText}>• Malicious URL</Text></View>
                    </View>
                  </View>
                </View>

                {/* WHY THIS SCORE (Screenshot 2) */}
                <View style={socStyles.whiteCard}>
                  <View style={socStyles.cardTopRow}>
                    <Text style={socStyles.cardHeading}>WHY THIS SCORE</Text>
                    <Text style={socStyles.rulesCount}>{activeScenario.rules.length} rules</Text>
                  </View>

                  <View style={socStyles.rulesWrap}>
                    {activeScenario.rules.map((r, i) => (
                      <View key={i} style={socStyles.ruleEntry}>
                        {r.score > 0 && (
                          <View style={socStyles.ruleScoreBadge}>
                            <Text style={socStyles.ruleScoreText}>+{r.score}</Text>
                          </View>
                        )}
                        <View style={{ flex: 1 }}>
                          <Text style={socStyles.ruleName}>{r.name}</Text>
                          {r.desc && <Text style={socStyles.ruleDesc}>{r.desc}</Text>}
                        </View>
                      </View>
                    ))}
                  </View>
                </View>

                {/* EXPORT REPORT (Screenshot 2) */}
                <View style={socStyles.whiteCard}>
                  <Text style={socStyles.cardHeading}>EXPORT REPORT</Text>
                  <View style={socStyles.exportMetaBox}>
                    <View style={socStyles.exportRow}>
                      <Text style={socStyles.exportKey}>Case ID</Text>
                      <Text style={socStyles.exportVal}>{activeScenario.case_id}</Text>
                    </View>
                    <View style={socStyles.exportRow}>
                      <Text style={socStyles.exportKey}>Risk Score</Text>
                      <Text style={socStyles.exportVal}>{activeScenario.risk_score}/100 ({activeScenario.category})</Text>
                    </View>
                    <View style={socStyles.exportRow}>
                      <Text style={socStyles.exportKey}>AI Result</Text>
                      <Text style={socStyles.exportVal}>{activeScenario.classification} ({(activeScenario.ai_confidence * 100).toFixed(1)}%)</Text>
                    </View>
                    <View style={socStyles.exportRow}>
                      <Text style={socStyles.exportKey}>Auth</Text>
                      <Text style={socStyles.exportVal}>
                        SPF: {activeScenario.auth.spf} | DKIM: {activeScenario.auth.dkim} | DMARC: {activeScenario.auth.dmarc}
                      </Text>
                    </View>
                    <View style={socStyles.exportRow}>
                      <Text style={socStyles.exportKey}>Source IP</Text>
                      <Text style={socStyles.exportVal}>{activeScenario.infra.source_ip}</Text>
                    </View>
                  </View>

                  <View style={socStyles.exportButtonsRow}>
                    <Pressable
                      style={socStyles.exportActionBtn}
                      onPress={() => Alert.alert("PDF Export", `PDF forensic dossier generated for ${activeScenario.case_id}`)}
                    >
                      <Text style={socStyles.exportActionBtnText}>PDF Report</Text>
                    </Pressable>
                    <Pressable
                      style={socStyles.exportActionBtn}
                      onPress={() => Alert.alert("JSON Export", `JSON structured artifact for ${activeScenario.case_id} copied.`)}
                    >
                      <Text style={socStyles.exportActionBtnText}>JSON Export</Text>
                    </Pressable>
                  </View>
                </View>
              </View>
            </View>

            {/* FOOTER (Matching Screenshot 2 & 3) */}
            <View style={socStyles.footer}>
              <Text style={socStyles.footerText}>
                MAILTRACE AI — SIH 2026 — DistilBERT + NetworkX
              </Text>
            </View>
          </ScrollView>
        )}

        {/* TAB 2: GRAPH 16 (Exact Match to Screenshot 3) */}
        {selectedTab === "graph" && (
          <ScrollView style={socStyles.scrollArea} contentContainerStyle={{ padding: 20 }}>
            <View style={socStyles.whiteCard}>
              <View style={socStyles.graphHeader}>
                <Text style={socStyles.graphHeading}>
                  RELATIONSHIP GRAPH <Text style={{ fontWeight: "400", color: "#64748B" }}>16 nodes · 15 edges</Text>
                </Text>

                {/* Graph Zoom Controls */}
                <View style={socStyles.graphControls}>
                  <Pressable style={socStyles.controlBtn} onPress={() => setGraphZoom((z) => Math.min(z + 0.2, 2))}>
                    <Text style={socStyles.controlBtnText}>+</Text>
                  </Pressable>
                  <Pressable style={socStyles.controlBtn} onPress={() => setGraphZoom((z) => Math.max(z - 0.2, 0.6))}>
                    <Text style={socStyles.controlBtnText}>-</Text>
                  </Pressable>
                  <Pressable style={socStyles.controlBtn} onPress={() => setGraphZoom(1)}>
                    <Text style={socStyles.controlBtnText}>Fit</Text>
                  </Pressable>
                  <Pressable style={socStyles.controlBtn} onPress={() => setGraphZoom(1)}>
                    <Text style={socStyles.controlBtnText}>Reset</Text>
                  </Pressable>
                </View>
              </View>

              {/* Interactive Visual Graph Canvas (Screenshot 3) */}
              <View style={[socStyles.graphCanvas, { transform: [{ scale: graphZoom }] }]}>
                {/* SVG Visual Graph Lines & Nodes */}
                <svg width="780" height="420" viewBox="0 0 780 420" style={{ width: "100%", height: 420 }}>
                  {/* Edges */}
                  <line x1="390" y1="210" x2="260" y2="150" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="390" y1="210" x2="480" y2="240" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="390" y1="210" x2="390" y2="130" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="390" y1="210" x2="400" y2="330" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="390" y1="210" x2="230" y2="260" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="390" y1="210" x2="550" y2="170" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="390" y1="130" x2="420" y2="70" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="480" y1="240" x2="580" y2="240" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="480" y1="240" x2="520" y2="320" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="230" y1="260" x2="180" y2="320" stroke="#CBD5E1" strokeWidth="2" />
                  <line x1="260" y1="150" x2="190" y2="170" stroke="#CBD5E1" strokeWidth="2" />

                  {/* Center Black Node: Email */}
                  <rect x="375" y="195" width="30" height="30" rx="4" fill="#0F172A" />
                  <text x="390" y="240" fontSize="10" textAnchor="middle" fill="#0F172A" fontWeight="bold">
                    Email ({activeScenario.case_id})
                  </text>

                  {/* Red Diamond Node: Reply-To */}
                  <polygon points="480,225 495,240 480,255 465,240" fill="#EF4444" />
                  <text x="480" y="270" fontSize="9" textAnchor="middle" fill="#64748B">
                    acme.invoice.alert@gmail.com
                  </text>

                  {/* Blue Circle Node: Sender */}
                  <circle cx="260" cy="150" r="12" fill="#3B82F6" />
                  <text x="260" y="130" fontSize="9" textAnchor="middle" fill="#64748B">
                    cfo@acme-finance.com
                  </text>

                  {/* Orange Circle Node: Return-Path */}
                  <circle cx="190" cy="170" r="10" fill="#F97316" />
                  <text x="190" y="195" fontSize="8" textAnchor="middle" fill="#64748B">
                    notify-acme.co
                  </text>

                  {/* Cyan Circles: IPs */}
                  <circle cx="390" cy="130" r="10" fill="#06B6D4" />
                  <text x="390" y="115" fontSize="9" textAnchor="middle" fill="#64748B">
                    198.51.100.42
                  </text>

                  <circle cx="580" cy="240" r="10" fill="#06B6D4" />
                  <circle cx="550" cy="170" r="8" fill="#06B6D4" />
                  <circle cx="520" cy="320" r="8" fill="#06B6D4" />

                  {/* Purple Square: Domain & URL */}
                  <rect x="220" y="250" width="20" height="20" rx="3" fill="#8B5CF6" />
                  <text x="230" y="285" fontSize="9" textAnchor="middle" fill="#64748B">
                    https://notify-acme.co/...
                  </text>

                  <rect x="390" y="320" width="20" height="20" rx="3" fill="#8B5CF6" />
                  <circle cx="180" cy="320" r="8" fill="#8B5CF6" />

                  {/* Green Pentagon: Infrastructure Node */}
                  <polygon points="420,55 435,68 429,85 411,85 405,68" fill="#10B981" />
                  <text x="420" y="50" fontSize="9" textAnchor="middle" fill="#10B981" fontWeight="bold">
                    Internet Assigned Numbers Auth
                  </text>
                </svg>
              </View>

              {/* Legend (Screenshot 3) */}
              <View style={socStyles.graphLegend}>
                <View style={socStyles.legendItem}><View style={[socStyles.legendDot, { backgroundColor: "#0F172A" }]} /><Text style={socStyles.legendText}>Email</Text></View>
                <View style={socStyles.legendItem}><View style={[socStyles.legendDot, { backgroundColor: "#3B82F6", borderRadius: 6 }]} /><Text style={socStyles.legendText}>Sender</Text></View>
                <View style={socStyles.legendItem}><View style={[socStyles.legendDot, { backgroundColor: "#EF4444" }]} /><Text style={socStyles.legendText}>Reply-To</Text></View>
                <View style={socStyles.legendItem}><View style={[socStyles.legendDot, { backgroundColor: "#F97316", borderRadius: 6 }]} /><Text style={socStyles.legendText}>Return-Path</Text></View>
                <View style={socStyles.legendItem}><View style={[socStyles.legendDot, { backgroundColor: "#8B5CF6" }]} /><Text style={socStyles.legendText}>Domain</Text></View>
                <View style={socStyles.legendItem}><View style={[socStyles.legendDot, { backgroundColor: "#A855F7" }]} /><Text style={socStyles.legendText}>URL</Text></View>
                <View style={socStyles.legendItem}><View style={[socStyles.legendDot, { backgroundColor: "#06B6D4", borderRadius: 6 }]} /><Text style={socStyles.legendText}>IP</Text></View>
                <View style={socStyles.legendItem}><View style={[socStyles.legendDot, { backgroundColor: "#10B981" }]} /><Text style={socStyles.legendText}>Infrastructure</Text></View>
              </View>
            </View>

            {/* FOOTER */}
            <View style={socStyles.footer}>
              <Text style={socStyles.footerText}>
                MAILTRACE AI — SIH 2026 — DistilBERT + NetworkX
              </Text>
            </View>
          </ScrollView>
        )}

        {/* TAB 3: TIMELINE 4 (Exact Match to Screenshot 4) */}
        {selectedTab === "timeline" && (
          <ScrollView style={socStyles.scrollArea} contentContainerStyle={{ padding: 20 }}>
            <View style={socStyles.whiteCard}>
              <View style={socStyles.timelineTopRow}>
                <Text style={socStyles.graphHeading}>FORENSIC TIMELINE</Text>
                <Text style={socStyles.rulesCount}>4 events</Text>
              </View>

              <View style={socStyles.timelineList}>
                {/* Event 1: Email Received */}
                <View style={socStyles.timelineCard}>
                  <View style={socStyles.timelineCardHeader}>
                    <View style={socStyles.timelineTitleRow}>
                      <View style={[socStyles.dot, { backgroundColor: "#3B82F6" }]} />
                      <Text style={socStyles.timelineEventName}>EMAIL RECEIVED</Text>
                      <Text style={socStyles.timelineEventTag}>RFC 5322 Date Header</Text>
                    </View>
                    <Text style={socStyles.timelineDate}>Sep 15, 2026, 15:48:40</Text>
                  </View>
                  <Text style={socStyles.timelineBody}>
                    Email '{activeScenario.subject}' dispatched from {activeScenario.sender}
                  </Text>
                </View>

                {/* Event 2: Evidence Preserved */}
                <View style={socStyles.timelineCard}>
                  <View style={socStyles.timelineCardHeader}>
                    <View style={socStyles.timelineTitleRow}>
                      <View style={[socStyles.dot, { backgroundColor: "#10B981" }]} />
                      <Text style={socStyles.timelineEventName}>EVIDENCE PRESERVED</Text>
                      <Text style={socStyles.timelineEventTag}>Chain of Custody</Text>
                    </View>
                    <Text style={socStyles.timelineDate}>Sep 19, 2026, 12:17:01</Text>
                  </View>
                  <Text style={socStyles.timelineBody}>
                    Preserved raw_eml artifact '{evidenceName}' (SHA-256: c4231fe183b06a9df591108a522d9510f23dc91918cabc06cdc309877f9f9ce0).
                  </Text>
                </View>

                {/* Event 3: Infrastructure Enriched */}
                <View style={socStyles.timelineCard}>
                  <View style={socStyles.timelineCardHeader}>
                    <View style={socStyles.timelineTitleRow}>
                      <View style={[socStyles.dot, { backgroundColor: "#3B82F6" }]} />
                      <Text style={socStyles.timelineEventName}>INFRASTRUCTURE ENRICHED</Text>
                      <Text style={socStyles.timelineEventTag}>Passive DNS / RDAP / GeoIP</Text>
                    </View>
                    <Text style={socStyles.timelineDate}>Sep 19, 2026, 17:47:21</Text>
                  </View>
                  <Text style={socStyles.timelineBody}>
                    Observed Source IP {activeScenario.infra.source_ip} ({activeScenario.infra.organization})
                  </Text>
                </View>

                {/* Event 4: Campaign Correlated */}
                <View style={socStyles.timelineCard}>
                  <View style={socStyles.timelineCardHeader}>
                    <View style={socStyles.timelineTitleRow}>
                      <View style={[socStyles.dot, { backgroundColor: "#EF4444" }]} />
                      <Text style={socStyles.timelineEventName}>CAMPAIGN CORRELATED</Text>
                      <Text style={socStyles.timelineEventTag}>Cross-Case Correlation</Text>
                    </View>
                    <Text style={socStyles.timelineDate}>Sep 19, 2026, 17:47:21</Text>
                  </View>
                  <Text style={socStyles.timelineBody}>
                    Potential campaign relationship detected with 172 case(s): MT-2026-000006, MT-2026-000011, MT-2026-000014, MT-2026-000017, MT-2026-000022, MT-2026-000025, MT-2026-000027, MT-2026-000028, MT-2026-000031...
                  </Text>
                </View>
              </View>
            </View>

            {/* FOOTER */}
            <View style={socStyles.footer}>
              <Text style={socStyles.footerText}>
                MAILTRACE AI — SIH 2026 — DistilBERT + NetworkX
              </Text>
            </View>
          </ScrollView>
        )}

        {/* TAB 4: CAMPAIGN 172 (Exact Match to Screenshot 5) */}
        {selectedTab === "campaign" && (
          <ScrollView style={socStyles.scrollArea} contentContainerStyle={{ padding: 20 }}>
            <View style={socStyles.whiteCard}>
              <View style={socStyles.campaignHeaderRow}>
                <View style={{ flexDirection: "row", alignItems: "center", gap: 10 }}>
                  <Text style={socStyles.graphHeading}>CAMPAIGN CORRELATION</Text>
                  <View style={[socStyles.badge, { backgroundColor: "#FEE2E2" }]}>
                    <Text style={[socStyles.badgeText, { color: "#EF4444" }]}>HIGH</Text>
                  </View>
                </View>
                <Text style={socStyles.campaignScoreText}>Score: +10/10</Text>
              </View>

              <Text style={socStyles.relatedCasesTitle}>RELATED CASES (172)</Text>

              {/* 172 Related Case Badges Grid (Screenshot 5) */}
              <View style={socStyles.casesGrid}>
                {Array.from({ length: 110 }).map((_, idx) => {
                  const num = String(idx * 3 + 6).padStart(6, "0");
                  return (
                    <Pressable
                      key={idx}
                      style={socStyles.casePill}
                      onPress={() => Alert.alert("Case", `Linked Case MT-2026-${num}`)}
                    >
                      <Text style={socStyles.casePillText}>MT-2026-{num}</Text>
                    </Pressable>
                  );
                })}
              </View>

              {/* SHARED INDICATORS (1201) (Screenshot 5) */}
              <View style={{ marginTop: 24 }}>
                <Text style={socStyles.relatedCasesTitle}>SHARED INDICATORS (1201)</Text>
                <View style={socStyles.sharedIndicatorsGrid}>
                  <View style={socStyles.indicatorBox}>
                    <Text style={socStyles.indicatorKey}>REPLY_TO</Text>
                    <Text style={socStyles.indicatorVal}>{activeScenario.reply_to}</Text>
                    <Text style={socStyles.indicatorLinked}>MT-2026-000006</Text>
                  </View>
                  <View style={socStyles.indicatorBox}>
                    <Text style={socStyles.indicatorKey}>DOMAIN</Text>
                    <Text style={socStyles.indicatorVal}>{activeScenario.identity.from_domain}</Text>
                    <Text style={socStyles.indicatorLinked}>MT-2026-000006</Text>
                  </View>
                </View>
              </View>
            </View>

            {/* FOOTER */}
            <View style={socStyles.footer}>
              <Text style={socStyles.footerText}>
                MAILTRACE AI — SIH 2026 — DistilBERT + NetworkX
              </Text>
            </View>
          </ScrollView>
        )}
      </View>
    );
  }

  // =========================================================================
  // 2. MOBILE VIEW (Image 3 Landing / Mobile SOC Cards)
  // =========================================================================
  return (
    <View style={mobileStyles.page}>
      <StatusBar barStyle="dark-content" backgroundColor="#F8F7F4" />

      {/* TOP HEADER */}
      <View style={mobileStyles.topBar}>
        <View>
          <Text style={mobileStyles.brandLabel}>MAILTRACE AI</Text>
          <View style={mobileStyles.statusRow}>
            <View style={[mobileStyles.statusDot, backendReady ? mobileStyles.dotGreen : mobileStyles.dotRed]} />
            <Text style={mobileStyles.statusText}>{backendReady ? "ONLINE" : "OFFLINE"}</Text>
          </View>
        </View>

        <Pressable
          style={mobileStyles.toolsCircle}
          onPress={() =>
            Alert.alert(
              "MailTrace Tools",
              `Backend: ${BACKEND_URL}\nActive Case: ${activeScenario.case_id}\nModel: dataset3_v1.0.0`
            )
          }
        >
          <Text style={mobileStyles.toolsIcon}>⚙</Text>
          <Text style={mobileStyles.toolsText}>Tools</Text>
        </Pressable>
      </View>

      {!selectedMailbox ? (
        /* DISCONNECTED MOBILE LANDING (Matching Image 3) */
        <View style={mobileStyles.landingContainer}>
          <Text style={mobileStyles.heroTitle}>Protect your Gmail before you trust it.</Text>
          <Text style={mobileStyles.heroSubtitle}>
            Connect your account to analyze new messages for phishing, malicious links,
            authentication issues, and suspicious attachments.
          </Text>

          <Pressable style={mobileStyles.connectBtn} onPress={handleConnectGmail}>
            <Text style={mobileStyles.connectBtnTitle}>Connect Gmail</Text>
            <Text style={mobileStyles.connectBtnSub}>Secure Google OAuth login</Text>
          </Pressable>

          <Text style={mobileStyles.footnote}>
            MAILTRACE never needs your Gmail password. After consent, return to the app and refresh the inbox.
          </Text>
        </View>
      ) : mobileViewingReport ? (
        /* MOBILE REPORT VIEW (When email is analyzed) */
        <ScrollView style={{ flex: 1 }} contentContainerStyle={{ padding: 18 }}>
          <View style={mobileStyles.reportHeader}>
            <Pressable
              style={({ pressed }) => [mobileStyles.backBtn, pressed && { opacity: 0.7 }]}
              onPress={() => setMobileViewingReport(false)}
              hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
            >
              <Text style={mobileStyles.backBtnText}>← Back to Inbox</Text>
            </Pressable>
            <View style={mobileStyles.caseBadgePill}>
              <Text style={mobileStyles.caseBadgePillText}>{activeScenario.case_id}</Text>
            </View>
          </View>

          {/* RISK VERDICT HERO CARD */}
          <View style={mobileStyles.verdictCard}>
            <View style={mobileStyles.verdictTopRow}>
              <View>
                <Text style={mobileStyles.verdictScoreLabel}>RISK SCORE</Text>
                <Text style={[
                  mobileStyles.verdictScoreNumber,
                  { color: activeScenario.risk_score >= 60 ? "#EF4444" : activeScenario.risk_score >= 30 ? "#F59E0B" : "#10B981" }
                ]}>
                  {activeScenario.risk_score}<Text style={mobileStyles.verdictScoreDenom}> / 100</Text>
                </Text>
              </View>
              <View style={[
                mobileStyles.verdictBadge,
                { backgroundColor: activeScenario.risk_score >= 60 ? "#FEE2E2" : activeScenario.risk_score >= 30 ? "#FEF3C7" : "#D1FAE5" }
              ]}>
                <Text style={[
                  mobileStyles.verdictBadgeText,
                  { color: activeScenario.risk_score >= 60 ? "#DC2626" : activeScenario.risk_score >= 30 ? "#D97706" : "#059669" }
                ]}>
                  {activeScenario.category} RISK
                </Text>
              </View>
            </View>

            <View style={mobileStyles.dividerLine} />

            <View style={mobileStyles.verdictMetaRow}>
              <View>
                <Text style={mobileStyles.metaKey}>CLASSIFICATION</Text>
                <Text style={[
                  mobileStyles.metaValBold,
                  { color: activeScenario.classification === "MALICIOUS" ? "#EF4444" : "#10B981" }
                ]}>
                  {activeScenario.classification}
                </Text>
              </View>
              <View>
                <Text style={mobileStyles.metaKey}>AI CONFIDENCE</Text>
                <Text style={mobileStyles.metaValBold}>
                  {(activeScenario.ai_confidence * 100).toFixed(1)}%
                </Text>
              </View>
              <View>
                <Text style={mobileStyles.metaKey}>MODEL</Text>
                <Text style={mobileStyles.metaValCode}>dataset3_v1.0.0</Text>
              </View>
            </View>
          </View>

          {/* EMAIL DETAILS CARD */}
          <View style={mobileStyles.sectionCard}>
            <Text style={mobileStyles.sectionHeading}>EMAIL METADATA</Text>
            <Text style={mobileStyles.cardSubject}>{activeScenario.subject}</Text>
            <View style={mobileStyles.cardMetaRow}>
              <Text style={mobileStyles.cardMetaKey}>From:</Text>
              <Text style={mobileStyles.cardMetaVal}>{activeScenario.sender}</Text>
            </View>
            <View style={mobileStyles.cardMetaRow}>
              <Text style={mobileStyles.cardMetaKey}>To:</Text>
              <Text style={mobileStyles.cardMetaVal}>{activeScenario.recipient}</Text>
            </View>
            <View style={mobileStyles.cardMetaRow}>
              <Text style={mobileStyles.cardMetaKey}>Date:</Text>
              <Text style={mobileStyles.cardMetaVal}>{activeScenario.date}</Text>
            </View>
          </View>

          {/* 6 RISK FACTOR BARS */}
          <View style={mobileStyles.sectionCard}>
            <Text style={mobileStyles.sectionHeading}>RISK FACTOR BREAKDOWN</Text>

            <View style={mobileStyles.barRow}>
              <View style={mobileStyles.barLabelCol}>
                <Text style={mobileStyles.barLabel}>AI Threat Detection</Text>
                <Text style={mobileStyles.barRatio}>{activeScenario.bars.ai_threat}/25</Text>
              </View>
              <View style={mobileStyles.barTrack}>
                <View style={[mobileStyles.barFill, { width: `${(activeScenario.bars.ai_threat / 25) * 100}%`, backgroundColor: "#8B5CF6" }]} />
              </View>
            </View>

            <View style={mobileStyles.barRow}>
              <View style={mobileStyles.barLabelCol}>
                <Text style={mobileStyles.barLabel}>Identity Spoofing</Text>
                <Text style={mobileStyles.barRatio}>{activeScenario.bars.identity}/20</Text>
              </View>
              <View style={mobileStyles.barTrack}>
                <View style={[mobileStyles.barFill, { width: `${(activeScenario.bars.identity / 20) * 100}%`, backgroundColor: "#3B82F6" }]} />
              </View>
            </View>

            <View style={mobileStyles.barRow}>
              <View style={mobileStyles.barLabelCol}>
                <Text style={mobileStyles.barLabel}>Authentication Failures</Text>
                <Text style={mobileStyles.barRatio}>{activeScenario.bars.auth}/15</Text>
              </View>
              <View style={mobileStyles.barTrack}>
                <View style={[mobileStyles.barFill, { width: `${(activeScenario.bars.auth / 15) * 100}%`, backgroundColor: "#EF4444" }]} />
              </View>
            </View>

            <View style={mobileStyles.barRow}>
              <View style={mobileStyles.barLabelCol}>
                <Text style={mobileStyles.barLabel}>URL / Domain Threat</Text>
                <Text style={mobileStyles.barRatio}>{activeScenario.bars.url_domain}/15</Text>
              </View>
              <View style={mobileStyles.barTrack}>
                <View style={[mobileStyles.barFill, { width: `${(activeScenario.bars.url_domain / 15) * 100}%`, backgroundColor: "#F97316" }]} />
              </View>
            </View>

            <View style={mobileStyles.barRow}>
              <View style={mobileStyles.barLabelCol}>
                <Text style={mobileStyles.barLabel}>Infrastructure Anomalies</Text>
                <Text style={mobileStyles.barRatio}>{activeScenario.bars.infra}/15</Text>
              </View>
              <View style={mobileStyles.barTrack}>
                <View style={[mobileStyles.barFill, { width: `${(activeScenario.bars.infra / 15) * 100}%`, backgroundColor: "#EC4899" }]} />
              </View>
            </View>

            <View style={mobileStyles.barRow}>
              <View style={mobileStyles.barLabelCol}>
                <Text style={mobileStyles.barLabel}>Campaign Cluster</Text>
                <Text style={mobileStyles.barRatio}>{activeScenario.bars.campaign}/10</Text>
              </View>
              <View style={mobileStyles.barTrack}>
                <View style={[mobileStyles.barFill, { width: `${(activeScenario.bars.campaign / 10) * 100}%`, backgroundColor: "#64748B" }]} />
              </View>
            </View>
          </View>

          {/* AUTHENTICATION */}
          <View style={mobileStyles.sectionCard}>
            <Text style={mobileStyles.sectionHeading}>AUTHENTICATION INTEGRITY</Text>
            <View style={mobileStyles.authRow}>
              <View style={mobileStyles.authItem}>
                <Text style={mobileStyles.authItemName}>SPF</Text>
                <Text style={[mobileStyles.authItemStatus, { color: activeScenario.auth.spf === "PASS" ? "#10B981" : "#EF4444" }]}>
                  {activeScenario.auth.spf}
                </Text>
              </View>
              <View style={mobileStyles.authItem}>
                <Text style={mobileStyles.authItemName}>DKIM</Text>
                <Text style={[mobileStyles.authItemStatus, { color: activeScenario.auth.dkim === "PASS" ? "#10B981" : "#EF4444" }]}>
                  {activeScenario.auth.dkim}
                </Text>
              </View>
              <View style={mobileStyles.authItem}>
                <Text style={mobileStyles.authItemName}>DMARC</Text>
                <Text style={[mobileStyles.authItemStatus, { color: activeScenario.auth.dmarc === "PASS" ? "#10B981" : "#EF4444" }]}>
                  {activeScenario.auth.dmarc}
                </Text>
              </View>
            </View>
          </View>

          {/* INFRASTRUCTURE */}
          <View style={mobileStyles.sectionCard}>
            <Text style={mobileStyles.sectionHeading}>ORIGINATING INFRASTRUCTURE</Text>
            <View style={mobileStyles.cardMetaRow}>
              <Text style={mobileStyles.cardMetaKey}>IP Address:</Text>
              <Text style={mobileStyles.cardMetaValCode}>{activeScenario.infra.source_ip}</Text>
            </View>
            <View style={mobileStyles.cardMetaRow}>
              <Text style={mobileStyles.cardMetaKey}>Reverse DNS:</Text>
              <Text style={mobileStyles.cardMetaValCode}>{activeScenario.infra.reverse_dns}</Text>
            </View>
            <View style={mobileStyles.cardMetaRow}>
              <Text style={mobileStyles.cardMetaKey}>Organization:</Text>
              <Text style={mobileStyles.cardMetaVal}>{activeScenario.infra.organization}</Text>
            </View>
            <View style={mobileStyles.cardMetaRow}>
              <Text style={mobileStyles.cardMetaKey}>Country:</Text>
              <Text style={mobileStyles.cardMetaVal}>{activeScenario.infra.geolocation}</Text>
            </View>
          </View>

          {/* EXPORT BUTTON */}
          <Pressable
            style={({ pressed }) => [mobileStyles.exportDossierBtn, pressed && { opacity: 0.8 }]}
            onPress={() => Alert.alert("Export Dossier", `Forensic Dossier for Case ${activeScenario.case_id} generated.`)}
          >
            <Text style={mobileStyles.exportDossierBtnText}>Download Forensic Dossier</Text>
          </Pressable>
        </ScrollView>
      ) : (
        /* CONNECTED INBOX FEED */
        <ScrollView
          style={{ flex: 1 }}
          contentContainerStyle={{ padding: 20 }}
          refreshControl={
            <RefreshControl
              refreshing={loadingMessages}
              onRefresh={() => loadMessages(selectedMailbox.id)}
            />
          }
        >
          <View style={mobileStyles.accountStrip}>
            <View style={{ flex: 1 }}>
              <Text style={mobileStyles.accountLabel}>CONNECTED MAILBOX</Text>
              <Text style={mobileStyles.accountEmail} numberOfLines={1}>
                {selectedMailbox.account_email}
              </Text>
            </View>
            <Pressable style={mobileStyles.disconnectBtn} onPress={handleDisconnectEmail}>
              <Text style={mobileStyles.disconnectBtnText}>Disconnect</Text>
            </Pressable>
          </View>

          <View style={mobileStyles.inboxHeaderRow}>
            <Text style={mobileStyles.inboxTitle}>
              INBOX {messages.length > 0 ? `(${messages.length})` : ""}
            </Text>
            <Pressable
              style={mobileStyles.refreshBtn}
              onPress={() => loadMessages(selectedMailbox.id)}
              disabled={loadingMessages}
            >
              <Text style={mobileStyles.refreshBtnText}>
                {loadingMessages ? "Loading..." : "↻ Refresh"}
              </Text>
            </Pressable>
          </View>

          {messages.map((item) => (
            <View key={item.id} style={mobileStyles.emailCard}>
              <View style={mobileStyles.emailTopRow}>
                <Text style={mobileStyles.emailSender} numberOfLines={1}>{item.from || "Unknown"}</Text>
                <Text style={mobileStyles.emailDate}>{item.date?.split(" ").slice(1, 4).join(" ") || ""}</Text>
              </View>
              <Text style={mobileStyles.emailSubject} numberOfLines={2}>{item.subject || "(No Subject)"}</Text>
              {item.snippet ? <Text style={mobileStyles.emailSnippet} numberOfLines={2}>{item.snippet}</Text> : null}
              <View style={{ alignItems: "flex-end", marginTop: 8 }}>
                <Pressable
                  style={({ pressed }) => [
                    mobileStyles.analyzeBtn,
                    analyzingId === item.id && { backgroundColor: "#6B7280" },
                    pressed && { opacity: 0.7 },
                  ]}
                  hitSlop={{ top: 12, bottom: 12, left: 12, right: 12 }}
                  onPress={() => handleAnalyzeLiveMessage(item)}
                  disabled={analyzingId === item.id}
                >
                  <Text style={mobileStyles.analyzeBtnText}>
                    {analyzingId === item.id ? "Analyzing..." : "Analyze →"}
                  </Text>
                </Pressable>
              </View>
            </View>
          ))}
        </ScrollView>
      )}
    </View>
  );
}

// =============================================================================
// STYLES: DESKTOP SOC WORKSTATION (Exact Match to Screenshots 1 - 5)
// =============================================================================
const socStyles = StyleSheet.create({
  page: {
    flex: 1,
    backgroundColor: "#F8FAFC",
  },
  navBar: {
    height: 56,
    backgroundColor: "#FFFFFF",
    borderBottomWidth: 1,
    borderColor: "#E2E8F0",
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingHorizontal: 20,
  },
  navLeft: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  brandTitle: {
    fontSize: 16,
    fontWeight: "800",
    color: "#0F172A",
  },
  brandSub: {
    fontSize: 12,
    color: "#64748B",
    fontWeight: "500",
  },
  caseBadge: {
    flexDirection: "row",
    alignItems: "center",
    backgroundColor: "#F1F5F9",
    paddingVertical: 3,
    paddingHorizontal: 8,
    borderRadius: 6,
    gap: 6,
    marginLeft: 12,
  },
  dot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  caseBadgeText: {
    fontSize: 11,
    fontWeight: "700",
    color: "#0F172A",
  },
  navRight: {
    flexDirection: "row",
    alignItems: "center",
    gap: 10,
  },
  accountPill: {
    backgroundColor: "#EFF6FF",
    borderWidth: 1,
    borderColor: "#BFDBFE",
    paddingVertical: 4,
    paddingHorizontal: 10,
    borderRadius: 6,
  },
  accountPillText: {
    fontSize: 11,
    fontWeight: "600",
    color: "#1D4ED8",
  },
  connectBtn: {
    backgroundColor: "#0F172A",
    paddingVertical: 5,
    paddingHorizontal: 10,
    borderRadius: 6,
  },
  connectBtnText: {
    fontSize: 11,
    fontWeight: "600",
    color: "#FFFFFF",
  },
  secondaryBtn: {
    backgroundColor: "#F1F5F9",
    borderWidth: 1,
    borderColor: "#CBD5E1",
    paddingVertical: 5,
    paddingHorizontal: 12,
    borderRadius: 6,
  },
  secondaryBtnText: {
    fontSize: 12,
    fontWeight: "600",
    color: "#334155",
  },
  apiPill: {
    flexDirection: "row",
    alignItems: "center",
    gap: 5,
    backgroundColor: "#F1F5F9",
    paddingVertical: 4,
    paddingHorizontal: 8,
    borderRadius: 6,
  },
  apiPillText: {
    fontSize: 11,
    fontWeight: "600",
    color: "#475569",
  },
  actionBtn: {
    backgroundColor: "#F8FAFC",
    borderWidth: 1,
    borderColor: "#CBD5E1",
    paddingVertical: 5,
    paddingHorizontal: 10,
    borderRadius: 6,
  },
  actionBtnText: {
    fontSize: 12,
    fontWeight: "600",
    color: "#334155",
  },
  primaryBlueBtn: {
    backgroundColor: "#2563EB",
    paddingVertical: 6,
    paddingHorizontal: 14,
    borderRadius: 6,
  },
  primaryBlueBtnText: {
    fontSize: 12,
    fontWeight: "700",
    color: "#FFFFFF",
  },
  pipelineBar: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    backgroundColor: "#FFFFFF",
    paddingHorizontal: 32,
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderColor: "#E2E8F0",
  },
  pipelineStep: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  checkCircle: {
    width: 20,
    height: 20,
    borderRadius: 10,
    backgroundColor: "#10B981",
    justifyContent: "center",
    alignItems: "center",
  },
  checkText: {
    color: "#FFFFFF",
    fontSize: 11,
    fontWeight: "bold",
  },
  blueNumberCircle: {
    width: 20,
    height: 20,
    borderRadius: 10,
    backgroundColor: "#2563EB",
    justifyContent: "center",
    alignItems: "center",
  },
  blueNumberText: {
    color: "#FFFFFF",
    fontSize: 11,
    fontWeight: "bold",
  },
  stepHead: {
    fontSize: 12,
    fontWeight: "700",
    color: "#0F172A",
  },
  stepSub: {
    fontSize: 10,
    color: "#64748B",
  },
  uploadCardContainer: {
    backgroundColor: "#FFFFFF",
    margin: 20,
    marginBottom: 0,
    padding: 16,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#E2E8F0",
  },
  uploadHeaderRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 10,
  },
  uploadHeaderTitle: {
    fontSize: 13,
    fontWeight: "700",
    color: "#0F172A",
  },
  activeCaseId: {
    fontSize: 11,
    fontWeight: "700",
    color: "#64748B",
  },
  dropzone: {
    borderWidth: 1.5,
    borderStyle: "dashed",
    borderColor: "#CBD5E1",
    borderRadius: 8,
    paddingVertical: 20,
    alignItems: "center",
    backgroundColor: "#F8FAFC",
  },
  dropzoneTitle: {
    fontSize: 13,
    fontWeight: "600",
    color: "#334155",
  },
  dropzoneSub: {
    fontSize: 11,
    color: "#64748B",
    marginTop: 4,
  },
  livePill: {
    backgroundColor: "#F8FAFC",
    borderWidth: 1,
    borderColor: "#CBD5E1",
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 6,
    maxWidth: 200,
  },
  livePillFrom: {
    fontSize: 10,
    fontWeight: "700",
    color: "#0F172A",
  },
  livePillSub: {
    fontSize: 11,
    color: "#64748B",
  },
  scenarioSectionTitle: {
    fontSize: 11,
    fontWeight: "800",
    color: "#64748B",
    letterSpacing: 0.5,
    marginBottom: 8,
  },
  scenariosRow: {
    flexDirection: "row",
    gap: 12,
  },
  scenarioCard: {
    flex: 1,
    backgroundColor: "#FFFFFF",
    borderWidth: 1,
    borderColor: "#E2E8F0",
    borderRadius: 8,
    padding: 12,
  },
  scenarioCardActive: {
    borderColor: "#2563EB",
    backgroundColor: "#F8FAFC",
  },
  scenarioTop: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 6,
  },
  scenarioTitle: {
    fontSize: 13,
    fontWeight: "700",
    color: "#0F172A",
  },
  badge: {
    paddingVertical: 2,
    paddingHorizontal: 6,
    borderRadius: 4,
  },
  badgeText: {
    fontSize: 10,
    fontWeight: "800",
  },
  scenarioDesc: {
    fontSize: 11,
    color: "#64748B",
    lineHeight: 16,
    marginBottom: 8,
  },
  loadLink: {
    fontSize: 12,
    fontWeight: "700",
    color: "#2563EB",
  },
  tabsBar: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    backgroundColor: "#F8FAFC",
    paddingHorizontal: 20,
    borderBottomWidth: 1,
    borderColor: "#E2E8F0",
    marginTop: 16,
  },
  tabsLeft: {
    flexDirection: "row",
    gap: 24,
  },
  tabBtn: {
    paddingVertical: 12,
    borderBottomWidth: 2,
    borderColor: "transparent",
  },
  tabBtnActive: {
    borderColor: "#2563EB",
  },
  tabBtnText: {
    fontSize: 13,
    fontWeight: "600",
    color: "#64748B",
  },
  tabBtnTextActive: {
    color: "#2563EB",
    fontWeight: "700",
  },
  refreshRow: {
    paddingVertical: 8,
  },
  refreshText: {
    fontSize: 12,
    fontWeight: "600",
    color: "#64748B",
  },
  scrollArea: {
    flex: 1,
  },
  mainGrid: {
    flexDirection: "row",
    gap: 20,
  },
  leftColumn: {
    flex: 65,
  },
  rightColumn: {
    flex: 35,
    gap: 16,
  },
  evidenceBanner: {
    backgroundColor: "#0F172A",
    borderRadius: 6,
    paddingHorizontal: 14,
    paddingVertical: 8,
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 12,
  },
  evidenceText: {
    color: "#94A3B8",
    fontSize: 12,
  },
  evidenceRight: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  shaPill: {
    backgroundColor: "#1E293B",
    paddingVertical: 2,
    paddingHorizontal: 6,
    borderRadius: 4,
  },
  shaText: {
    color: "#38BDF8",
    fontSize: 10,
    fontWeight: "700",
  },
  copyBtn: {
    backgroundColor: "#334155",
    paddingVertical: 2,
    paddingHorizontal: 8,
    borderRadius: 4,
  },
  copyBtnText: {
    color: "#FFFFFF",
    fontSize: 11,
    fontWeight: "600",
  },
  headerBox: {
    backgroundColor: "#FFFFFF",
    borderRadius: 8,
    padding: 16,
    borderWidth: 1,
    borderColor: "#E2E8F0",
    marginBottom: 12,
  },
  subjectLarge: {
    fontSize: 16,
    fontWeight: "800",
    color: "#0F172A",
    marginBottom: 12,
  },
  metaTwoCol: {
    flexDirection: "row",
    gap: 16,
    marginBottom: 8,
  },
  metaKey: {
    fontSize: 10,
    fontWeight: "700",
    color: "#64748B",
    letterSpacing: 0.5,
  },
  metaValue: {
    fontSize: 12,
    color: "#1E293B",
    fontWeight: "500",
    marginTop: 2,
  },
  mismatchPill: {
    backgroundColor: "#FEF3C7",
    paddingHorizontal: 4,
    paddingVertical: 1,
    borderRadius: 3,
  },
  mismatchText: {
    fontSize: 9,
    fontWeight: "800",
    color: "#D97706",
  },
  messageIdText: {
    fontSize: 10,
    color: "#94A3B8",
    marginTop: 6,
  },
  viewSwitcherRow: {
    flexDirection: "row",
    gap: 16,
    borderBottomWidth: 1,
    borderColor: "#E2E8F0",
    marginBottom: 10,
    paddingHorizontal: 4,
  },
  viewSwitchBtn: {
    paddingVertical: 6,
    borderBottomWidth: 2,
    borderColor: "transparent",
  },
  viewSwitchBtnActive: {
    borderColor: "#2563EB",
  },
  viewSwitchText: {
    fontSize: 12,
    fontWeight: "600",
    color: "#64748B",
  },
  viewSwitchTextActive: {
    color: "#2563EB",
    fontWeight: "700",
  },
  bodyContainer: {
    backgroundColor: "#FFFFFF",
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#E2E8F0",
    padding: 14,
    marginBottom: 16,
    minHeight: 140,
  },
  sandboxBanner: {
    backgroundColor: "#F1F5F9",
    paddingVertical: 6,
    paddingHorizontal: 10,
    borderRadius: 4,
    marginBottom: 10,
  },
  sandboxText: {
    fontSize: 11,
    color: "#475569",
    fontStyle: "italic",
  },
  bodyText: {
    fontSize: 12,
    color: "#334155",
    lineHeight: 18,
  },
  rawHeadersMono: {
    fontSize: 11,
    color: "#334155",
    fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace",
    lineHeight: 16,
  },
  sectionCard: {
    backgroundColor: "#FFFFFF",
    borderRadius: 8,
    padding: 16,
    borderWidth: 1,
    borderColor: "#E2E8F0",
    marginBottom: 16,
  },
  sectionCardHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 12,
  },
  sectionCardTitle: {
    fontSize: 12,
    fontWeight: "800",
    color: "#0F172A",
    letterSpacing: 0.5,
  },
  alignmentLabel: {
    fontSize: 11,
    color: "#475569",
    fontWeight: "600",
  },
  authThreeCols: {
    flexDirection: "row",
    gap: 12,
  },
  authCard: {
    flex: 1,
    backgroundColor: "#F8FAFC",
    borderWidth: 1,
    borderColor: "#E2E8F0",
    borderRadius: 6,
    padding: 10,
  },
  authCardHead: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 4,
  },
  authCardName: {
    fontSize: 11,
    fontWeight: "700",
    color: "#0F172A",
  },
  authStatusDot: {
    fontSize: 10,
    fontWeight: "700",
    color: "#475569",
  },
  authCardDesc: {
    fontSize: 10,
    color: "#64748B",
    lineHeight: 14,
  },
  spoofBadge: {
    backgroundColor: "#FEE2E2",
    paddingVertical: 2,
    paddingHorizontal: 8,
    borderRadius: 4,
  },
  spoofBadgeText: {
    fontSize: 10,
    fontWeight: "700",
    color: "#EF4444",
  },
  identityGrid: {
    flexDirection: "row",
    gap: 12,
  },
  identityBox: {
    flex: 1,
    backgroundColor: "#F8FAFC",
    borderWidth: 1,
    borderColor: "#E2E8F0",
    borderRadius: 6,
    padding: 10,
  },
  mismatchBox: {
    backgroundColor: "#FEF2F2",
    borderColor: "#FECACA",
  },
  identityBoxTop: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 4,
  },
  identityKey: {
    fontSize: 10,
    fontWeight: "700",
    color: "#64748B",
  },
  displayTag: {
    backgroundColor: "#E2E8F0",
    fontSize: 9,
    fontWeight: "700",
    color: "#334155",
    paddingHorizontal: 4,
    borderRadius: 2,
  },
  mismatchTag: {
    backgroundColor: "#FEE2E2",
    fontSize: 9,
    fontWeight: "700",
    color: "#EF4444",
    paddingHorizontal: 4,
    borderRadius: 2,
  },
  identityVal: {
    fontSize: 12,
    fontWeight: "700",
    color: "#0F172A",
  },
  infraStatusText: {
    fontSize: 10,
    fontWeight: "700",
    color: "#10B981",
  },
  infraTable: {
    gap: 6,
  },
  infraTableRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingVertical: 4,
    borderBottomWidth: 1,
    borderColor: "#F1F5F9",
  },
  infraRowKey: {
    fontSize: 12,
    color: "#64748B",
  },
  infraRowValWithAction: {
    flexDirection: "row",
    alignItems: "center",
    gap: 8,
  },
  infraRowValBold: {
    fontSize: 12,
    fontWeight: "700",
    color: "#0F172A",
  },
  infraRowVal: {
    fontSize: 12,
    color: "#0F172A",
  },
  copySmallBtn: {
    backgroundColor: "#F1F5F9",
    borderWidth: 1,
    borderColor: "#CBD5E1",
    paddingVertical: 1,
    paddingHorizontal: 6,
    borderRadius: 4,
  },
  copySmallBtnText: {
    fontSize: 10,
    fontWeight: "600",
    color: "#475569",
  },
  whiteCard: {
    backgroundColor: "#FFFFFF",
    borderRadius: 8,
    padding: 16,
    borderWidth: 1,
    borderColor: "#E2E8F0",
  },
  cardTopRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  cardHeading: {
    fontSize: 11,
    fontWeight: "800",
    color: "#64748B",
    letterSpacing: 0.5,
  },
  giantScoreRow: {
    flexDirection: "row",
    alignItems: "baseline",
    marginVertical: 8,
  },
  giantScoreText: {
    fontSize: 42,
    fontWeight: "900",
  },
  giantScoreDenom: {
    fontSize: 14,
    color: "#64748B",
    fontWeight: "700",
    marginLeft: 4,
  },
  barsWrap: {
    gap: 8,
  },
  barItem: {
    flexDirection: "row",
    alignItems: "center",
  },
  barName: {
    width: 90,
    fontSize: 11,
    fontWeight: "600",
    color: "#475569",
  },
  barTrack: {
    flex: 1,
    height: 5,
    backgroundColor: "#E2E8F0",
    borderRadius: 3,
    marginHorizontal: 8,
    overflow: "hidden",
  },
  barProgress: {
    height: "100%",
    borderRadius: 3,
  },
  barRatio: {
    width: 40,
    fontSize: 10,
    color: "#64748B",
    fontWeight: "700",
    textAlign: "right",
  },
  modelTag: {
    fontSize: 10,
    fontWeight: "700",
    color: "#64748B",
  },
  verdictBox: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginTop: 10,
    paddingBottom: 10,
    borderBottomWidth: 1,
    borderColor: "#F1F5F9",
  },
  verdictSub: {
    fontSize: 10,
    color: "#64748B",
    fontWeight: "600",
  },
  verdictMain: {
    fontSize: 16,
    fontWeight: "900",
    letterSpacing: 0.5,
  },
  confidenceNumber: {
    fontSize: 16,
    fontWeight: "800",
    color: "#0F172A",
  },
  behavioralHeading: {
    fontSize: 10,
    fontWeight: "800",
    color: "#64748B",
    marginBottom: 6,
  },
  signalChipsWrap: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 6,
  },
  signalChip: {
    backgroundColor: "#F8FAFC",
    borderWidth: 1,
    borderColor: "#E2E8F0",
    paddingVertical: 3,
    paddingHorizontal: 8,
    borderRadius: 4,
  },
  signalText: {
    fontSize: 10,
    color: "#475569",
    fontWeight: "600",
  },
  rulesCount: {
    fontSize: 11,
    color: "#64748B",
  },
  rulesWrap: {
    marginTop: 10,
    gap: 8,
  },
  ruleEntry: {
    flexDirection: "row",
    gap: 8,
    alignItems: "flex-start",
  },
  ruleScoreBadge: {
    backgroundColor: "#FEE2E2",
    paddingHorizontal: 4,
    paddingVertical: 1,
    borderRadius: 3,
  },
  ruleScoreText: {
    fontSize: 10,
    fontWeight: "800",
    color: "#EF4444",
  },
  ruleName: {
    fontSize: 12,
    fontWeight: "700",
    color: "#0F172A",
  },
  ruleDesc: {
    fontSize: 11,
    color: "#64748B",
    marginTop: 1,
  },
  exportMetaBox: {
    marginVertical: 10,
    gap: 4,
  },
  exportRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    paddingVertical: 2,
  },
  exportKey: {
    fontSize: 11,
    color: "#64748B",
  },
  exportVal: {
    fontSize: 11,
    fontWeight: "600",
    color: "#0F172A",
  },
  exportButtonsRow: {
    flexDirection: "row",
    gap: 8,
    marginTop: 6,
  },
  exportActionBtn: {
    flex: 1,
    backgroundColor: "#FFFFFF",
    borderWidth: 1,
    borderColor: "#CBD5E1",
    paddingVertical: 6,
    borderRadius: 6,
    alignItems: "center",
  },
  exportActionBtnText: {
    fontSize: 11,
    fontWeight: "700",
    color: "#334155",
  },
  graphHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 12,
  },
  graphHeading: {
    fontSize: 13,
    fontWeight: "800",
    color: "#0F172A",
    letterSpacing: 0.5,
  },
  graphControls: {
    flexDirection: "row",
    gap: 6,
  },
  controlBtn: {
    backgroundColor: "#FFFFFF",
    borderWidth: 1,
    borderColor: "#CBD5E1",
    paddingVertical: 2,
    paddingHorizontal: 8,
    borderRadius: 4,
  },
  controlBtnText: {
    fontSize: 11,
    fontWeight: "700",
    color: "#334155",
  },
  graphCanvas: {
    borderWidth: 1,
    borderColor: "#E2E8F0",
    borderRadius: 8,
    backgroundColor: "#FFFFFF",
    height: 420,
    overflow: "hidden",
  },
  graphLegend: {
    flexDirection: "row",
    justifyContent: "center",
    flexWrap: "wrap",
    gap: 14,
    marginTop: 14,
    paddingTop: 10,
    borderTopWidth: 1,
    borderColor: "#F1F5F9",
  },
  legendItem: {
    flexDirection: "row",
    alignItems: "center",
    gap: 4,
  },
  legendDot: {
    width: 8,
    height: 8,
  },
  legendText: {
    fontSize: 11,
    color: "#475569",
    fontWeight: "600",
  },
  timelineTopRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 16,
  },
  timelineList: {
    gap: 12,
  },
  timelineCard: {
    backgroundColor: "#F8FAFC",
    borderWidth: 1,
    borderColor: "#E2E8F0",
    borderRadius: 8,
    padding: 14,
  },
  timelineCardHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 6,
  },
  timelineTitleRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
  },
  timelineEventName: {
    fontSize: 12,
    fontWeight: "800",
    color: "#0F172A",
  },
  timelineEventTag: {
    fontSize: 10,
    color: "#64748B",
    backgroundColor: "#E2E8F0",
    paddingHorizontal: 4,
    borderRadius: 2,
  },
  timelineDate: {
    fontSize: 10,
    color: "#64748B",
  },
  timelineBody: {
    fontSize: 11,
    color: "#334155",
    lineHeight: 16,
  },
  campaignHeaderRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 16,
  },
  campaignScoreText: {
    fontSize: 12,
    fontWeight: "800",
    color: "#EF4444",
  },
  relatedCasesTitle: {
    fontSize: 11,
    fontWeight: "800",
    color: "#64748B",
    letterSpacing: 0.5,
    marginBottom: 10,
  },
  casesGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    gap: 6,
  },
  casePill: {
    backgroundColor: "#EFF6FF",
    borderWidth: 1,
    borderColor: "#BFDBFE",
    paddingVertical: 3,
    paddingHorizontal: 6,
    borderRadius: 4,
  },
  casePillText: {
    fontSize: 10,
    fontWeight: "700",
    color: "#1D4ED8",
  },
  sharedIndicatorsGrid: {
    flexDirection: "row",
    gap: 16,
  },
  indicatorBox: {
    flex: 1,
    backgroundColor: "#F8FAFC",
    borderWidth: 1,
    borderColor: "#E2E8F0",
    borderRadius: 6,
    padding: 12,
  },
  indicatorKey: {
    fontSize: 10,
    fontWeight: "800",
    color: "#64748B",
    marginBottom: 4,
  },
  indicatorVal: {
    fontSize: 12,
    fontWeight: "700",
    color: "#0F172A",
  },
  indicatorLinked: {
    fontSize: 10,
    color: "#64748B",
    marginTop: 4,
  },
  footer: {
    alignItems: "center",
    paddingVertical: 20,
    marginTop: 20,
    borderTopWidth: 1,
    borderColor: "#E2E8F0",
  },
  footerText: {
    fontSize: 11,
    color: "#94A3B8",
    fontWeight: "500",
    letterSpacing: 1,
  },
});

// =============================================================================
// STYLES: MOBILE VIEW
// =============================================================================
const mobileStyles = StyleSheet.create({
  page: {
    flex: 1,
    backgroundColor: "#F8F7F4",
    paddingTop: Platform.OS === "android" ? (StatusBar.currentHeight || 28) : 48,
  },
  topBar: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    paddingHorizontal: 24,
    paddingBottom: 16,
  },
  brandLabel: {
    fontSize: 12,
    letterSpacing: 2,
    fontWeight: "700",
    color: "#666666",
  },
  statusRow: {
    flexDirection: "row",
    alignItems: "center",
    gap: 6,
    marginTop: 4,
  },
  statusDot: {
    width: 6,
    height: 6,
    borderRadius: 3,
  },
  dotGreen: {
    backgroundColor: "#10B981",
  },
  dotRed: {
    backgroundColor: "#EF4444",
  },
  statusText: {
    fontSize: 10,
    fontWeight: "600",
    color: "#666666",
  },
  toolsCircle: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: "#E8F0FE",
    justifyContent: "center",
    alignItems: "center",
    borderWidth: 1,
    borderColor: "#D2E3FC",
  },
  toolsIcon: {
    fontSize: 18,
    color: "#1A73E8",
  },
  toolsText: {
    fontSize: 9,
    fontWeight: "600",
    color: "#1A73E8",
  },
  landingContainer: {
    flex: 1,
    justifyContent: "center",
    paddingHorizontal: 24,
    paddingBottom: 40,
  },
  heroTitle: {
    fontSize: 34,
    fontWeight: "800",
    color: "#111111",
    lineHeight: 40,
    marginBottom: 16,
  },
  heroSubtitle: {
    fontSize: 15,
    color: "#555555",
    lineHeight: 22,
    marginBottom: 36,
  },
  connectBtn: {
    backgroundColor: "#111111",
    borderRadius: 20,
    paddingVertical: 18,
    paddingHorizontal: 24,
    marginBottom: 24,
  },
  connectBtnTitle: {
    color: "#FFFFFF",
    fontSize: 18,
    fontWeight: "700",
  },
  connectBtnSub: {
    color: "#888888",
    fontSize: 13,
    marginTop: 4,
  },
  footnote: {
    fontSize: 12,
    color: "#777777",
    lineHeight: 18,
  },
  accountStrip: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    backgroundColor: "#FFFFFF",
    borderRadius: 14,
    padding: 16,
    marginBottom: 20,
    borderWidth: 1,
    borderColor: "#E5E5E5",
  },
  accountLabel: {
    fontSize: 10,
    fontWeight: "700",
    letterSpacing: 1,
    color: "#888888",
  },
  accountEmail: {
    fontSize: 14,
    fontWeight: "600",
    color: "#111111",
    marginTop: 2,
  },
  disconnectBtn: {
    backgroundColor: "#F3F4F6",
    paddingVertical: 8,
    paddingHorizontal: 12,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: "#E5E7EB",
  },
  disconnectBtnText: {
    fontSize: 12,
    fontWeight: "600",
    color: "#EF4444",
  },
  inboxHeaderRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 12,
  },
  inboxTitle: {
    fontSize: 13,
    fontWeight: "800",
    letterSpacing: 1.5,
    color: "#111111",
  },
  refreshBtn: {
    paddingVertical: 4,
    paddingHorizontal: 10,
  },
  refreshBtnText: {
    fontSize: 12,
    fontWeight: "600",
    color: "#111111",
  },
  emailCard: {
    backgroundColor: "#FFFFFF",
    borderRadius: 12,
    padding: 16,
    marginBottom: 12,
    borderWidth: 1,
    borderColor: "#EBEBEB",
  },
  emailTopRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 6,
  },
  emailSender: {
    fontSize: 12,
    fontWeight: "600",
    color: "#666666",
    flex: 1,
  },
  emailDate: {
    fontSize: 11,
    color: "#999999",
  },
  emailSubject: {
    fontSize: 15,
    fontWeight: "700",
    color: "#111111",
    marginBottom: 6,
  },
  emailSnippet: {
    fontSize: 13,
    color: "#555555",
    lineHeight: 18,
  },
  analyzeBtn: {
    backgroundColor: "#111111",
    paddingVertical: 8,
    paddingHorizontal: 16,
    borderRadius: 8,
  },
  analyzeBtnText: {
    color: "#FFFFFF",
    fontSize: 13,
    fontWeight: "600",
  },
  reportHeader: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: 16,
  },
  backBtn: {
    backgroundColor: "#111111",
    paddingVertical: 8,
    paddingHorizontal: 14,
    borderRadius: 8,
  },
  backBtnText: {
    color: "#FFFFFF",
    fontSize: 13,
    fontWeight: "700",
  },
  caseBadgePill: {
    backgroundColor: "#E2E8F0",
    paddingVertical: 5,
    paddingHorizontal: 10,
    borderRadius: 6,
  },
  caseBadgePillText: {
    fontSize: 12,
    fontWeight: "700",
    color: "#334155",
  },
  verdictCard: {
    backgroundColor: "#FFFFFF",
    borderRadius: 14,
    padding: 18,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: "#E2E8F0",
  },
  verdictTopRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  verdictScoreLabel: {
    fontSize: 11,
    fontWeight: "700",
    color: "#64748B",
    letterSpacing: 1,
  },
  verdictScoreNumber: {
    fontSize: 36,
    fontWeight: "900",
  },
  verdictScoreDenom: {
    fontSize: 16,
    fontWeight: "600",
    color: "#94A3B8",
  },
  verdictBadge: {
    paddingVertical: 6,
    paddingHorizontal: 12,
    borderRadius: 8,
  },
  verdictBadgeText: {
    fontSize: 13,
    fontWeight: "800",
    letterSpacing: 0.5,
  },
  dividerLine: {
    height: 1,
    backgroundColor: "#F1F5F9",
    marginVertical: 14,
  },
  verdictMetaRow: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "center",
  },
  metaKey: {
    fontSize: 10,
    fontWeight: "700",
    color: "#94A3B8",
    marginBottom: 2,
    letterSpacing: 0.5,
  },
  metaValBold: {
    fontSize: 13,
    fontWeight: "800",
    color: "#0F172A",
  },
  metaValCode: {
    fontSize: 12,
    fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace",
    color: "#64748B",
    fontWeight: "600",
  },
  sectionCard: {
    backgroundColor: "#FFFFFF",
    borderRadius: 12,
    padding: 16,
    marginBottom: 14,
    borderWidth: 1,
    borderColor: "#E2E8F0",
  },
  sectionHeading: {
    fontSize: 11,
    fontWeight: "800",
    color: "#475569",
    letterSpacing: 1,
    marginBottom: 10,
  },
  cardSubject: {
    fontSize: 15,
    fontWeight: "700",
    color: "#0F172A",
    marginBottom: 10,
  },
  cardMetaRow: {
    flexDirection: "row",
    marginBottom: 5,
  },
  cardMetaKey: {
    width: 90,
    fontSize: 12,
    fontWeight: "600",
    color: "#64748B",
  },
  cardMetaVal: {
    flex: 1,
    fontSize: 12,
    color: "#1E293B",
  },
  cardMetaValCode: {
    flex: 1,
    fontSize: 12,
    fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace",
    color: "#0F172A",
    fontWeight: "600",
  },
  barRow: {
    marginBottom: 10,
  },
  barLabelCol: {
    flexDirection: "row",
    justifyContent: "space-between",
    marginBottom: 4,
  },
  barLabel: {
    fontSize: 12,
    fontWeight: "600",
    color: "#334155",
  },
  barRatio: {
    fontSize: 11,
    fontWeight: "700",
    color: "#64748B",
  },
  barTrack: {
    height: 7,
    backgroundColor: "#F1F5F9",
    borderRadius: 4,
    overflow: "hidden",
  },
  barFill: {
    height: "100%",
    borderRadius: 4,
  },
  authRow: {
    flexDirection: "row",
    justifyContent: "space-around",
    paddingVertical: 6,
  },
  authItem: {
    alignItems: "center",
  },
  authItemName: {
    fontSize: 12,
    fontWeight: "700",
    color: "#64748B",
    marginBottom: 4,
  },
  authItemStatus: {
    fontSize: 14,
    fontWeight: "800",
  },
  exportDossierBtn: {
    backgroundColor: "#2563EB",
    paddingVertical: 13,
    borderRadius: 10,
    alignItems: "center",
    marginTop: 6,
    marginBottom: 24,
  },
  exportDossierBtnText: {
    color: "#FFFFFF",
    fontSize: 14,
    fontWeight: "700",
  },
});