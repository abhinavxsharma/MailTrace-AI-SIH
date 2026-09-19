import React from "react";
import {
  Pressable,
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
} from "react-native";

const COLORS = {
  background: "#F5F3EE",
  surface: "#FFFFFF",
  black: "#111111",
  dark: "#181818",
  muted: "#686868",
  softMuted: "#8A8A8A",
  border: "#E2DFD8",
  light: "#EEECE6",
  white: "#FFFFFF",
  success: "#1E8A52",
};

export default function App() {
  const handleConnectGmail = () => {
    // TODO:
    // Connect this to the real Gmail OAuth endpoint
    // from your backend.
    console.log("Connect Gmail");
  };

  return (
    <SafeAreaView style={styles.safeArea}>
      <StatusBar barStyle="dark-content" backgroundColor={COLORS.background} />

      <ScrollView
        contentContainerStyle={styles.scrollContent}
        showsVerticalScrollIndicator={false}
      >
        {/* =========================================================
            HEADER
        ========================================================= */}
        <View style={styles.header}>
          <View style={styles.brandRow}>
            <View style={styles.logoMark}>
              <View style={styles.logoEnvelope}>
                <View style={styles.logoEnvelopeLineLeft} />
                <View style={styles.logoEnvelopeLineRight} />
              </View>

              <View style={styles.logoDot} />
            </View>

            <View style={styles.brandTextWrap}>
              <Text style={styles.brandName}>
                MAILTRACE <Text style={styles.brandAi}>AI</Text>
              </Text>

              <Text style={styles.brandTagline}>
                SEE RISK BEFORE YOU CLICK
              </Text>
            </View>
          </View>

          <View style={styles.statusPill}>
            <View style={styles.statusDot} />

            <View>
              <Text style={styles.statusTitle}>Ready to Protect</Text>
              <Text style={styles.statusSubtitle}>Your inbox, safer.</Text>
            </View>
          </View>
        </View>

        {/* =========================================================
            HERO
        ========================================================= */}
        <View style={styles.hero}>
          <View style={styles.eyebrow}>
            <Text style={styles.eyebrowText}>
              AI-POWERED EMAIL SECURITY
            </Text>
          </View>

          <Text style={styles.heroTitle}>
            Protect your{"\n"}Gmail before{"\n"}you trust it.
          </Text>

          <Text style={styles.heroDescription}>
            MAILTRACE analyzes your incoming emails in real time and gives
            you a clear security verdict — before you even open them.
          </Text>

          {/* Minimal monochrome security graphic */}
          <View style={styles.securityIllustration}>
            <View style={styles.illustrationRingOuter} />
            <View style={styles.illustrationRingMiddle} />
            <View style={styles.illustrationCardBack} />

            <View style={styles.illustrationCard}>
              <View style={styles.mailIcon}>
                <View style={styles.mailTopLeft} />
                <View style={styles.mailTopRight} />

                <Text style={styles.mailG}>G</Text>
              </View>
            </View>

            <View style={[styles.signal, styles.signalTop]}>
              <Text style={styles.signalIcon}>!</Text>
              <Text style={styles.signalText}>Phishing?</Text>
            </View>

            <View style={[styles.signal, styles.signalRight]}>
              <Text style={styles.signalIcon}>↗</Text>
              <Text style={styles.signalText}>Suspicious{"\n"}link?</Text>
            </View>

            <View style={[styles.signal, styles.signalBottom]}>
              <Text style={styles.signalIcon}>✓</Text>
              <Text style={styles.signalText}>Safe?</Text>
            </View>

            <View style={styles.illustrationArrow}>
              <Text style={styles.illustrationArrowText}>↗</Text>
              <Text style={styles.illustrationNote}>
                Know before{"\n"}you click
              </Text>
            </View>
          </View>

          {/* Three small benefits */}
          <View style={styles.benefitsRow}>
            <Benefit
              icon="ϟ"
              title="Real-time"
              subtitle="analysis"
            />

            <View style={styles.benefitDivider} />

            <Benefit
              icon="◇"
              title="Detects"
              subtitle="hidden risks"
            />

            <View style={styles.benefitDivider} />

            <Benefit
              icon="○"
              title="You stay"
              subtitle="in control"
            />
          </View>
        </View>

        {/* =========================================================
            CONNECT GMAIL
        ========================================================= */}
        <Pressable
          onPress={handleConnectGmail}
          style={({ pressed }) => [
            styles.gmailCard,
            pressed && styles.gmailCardPressed,
          ]}
        >
          <View style={styles.gmailLogoBox}>
            <Text style={styles.gmailLogoRed}>M</Text>
          </View>

          <View style={styles.gmailContent}>
            <Text style={styles.gmailTitle}>Connect Gmail</Text>

            <Text style={styles.gmailSubtitle}>
              Securely connect your Gmail account{"\n"}
              and let MAILTRACE do the rest.
            </Text>
          </View>

          <View style={styles.gmailArrow}>
            <Text style={styles.gmailArrowText}>→</Text>
          </View>
        </Pressable>

        {/* =========================================================
            SECURITY NOTE
        ========================================================= */}
        <View style={styles.securityNote}>
          <View style={styles.lockCircle}>
            <Text style={styles.lockIcon}>▣</Text>
          </View>

          <Text style={styles.securityNoteText}>
            Your Gmail credentials are handled through secure
            authentication. We never store your password.
          </Text>

          <View style={styles.infoCircle}>
            <Text style={styles.infoText}>i</Text>
          </View>
        </View>

        {/* =========================================================
            WHAT MAILTRACE CHECKS
        ========================================================= */}
        <View style={styles.sectionHeader}>
          <Text style={styles.sectionTitle}>What MAILTRACE checks</Text>

          <View style={styles.sectionLine} />

          <Text style={styles.sectionCaption}>BUILT FOR A SAFER YOU</Text>
        </View>

        <View style={styles.checkGrid}>
          <CheckCard
            icon="◉"
            title="Suspicious senders"
            description="Detects spoofed and impersonated senders"
          />

          <CheckCard
            icon="↗"
            title="Malicious links"
            description="Checks links for phishing and harmful websites"
          />

          <CheckCard
            icon="▤"
            title="SPF, DKIM & DMARC"
            description="Verifies email authentication"
          />

          <CheckCard
            icon="⌁"
            title="Suspicious attachments"
            description="Identifies potentially dangerous files"
          />
        </View>

        {/* =========================================================
            BRAND BANNER
        ========================================================= */}
        <View style={styles.brandBanner}>
          <View style={styles.bannerTextWrap}>
            <Text style={styles.bannerLine}>SAFER EMAILS.</Text>
            <Text style={styles.bannerLine}>SMARTER DECISIONS.</Text>
            <Text style={styles.bannerLine}>A MORE SECURE YOU.</Text>
          </View>

          <View style={styles.bannerGraphic}>
            <View style={styles.mountainOne} />
            <View style={styles.mountainTwo} />
            <View style={styles.mountainThree} />
          </View>
        </View>

        {/* =========================================================
            FOOTER
        ========================================================= */}
        <View style={styles.footer}>
          <Text style={styles.footerText}>
            MAILTRACE AI
          </Text>

          <Text style={styles.footerDivider}>|</Text>

          <Text style={styles.footerText}>
            FOR A SAFER DIGITAL INDIA
          </Text>

          <Text style={styles.indiaFlag}>🇮🇳</Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

/* ===============================================================
   BENEFIT
================================================================ */

function Benefit({
  icon,
  title,
  subtitle,
}: {
  icon: string;
  title: string;
  subtitle: string;
}) {
  return (
    <View style={styles.benefit}>
      <View style={styles.benefitIcon}>
        <Text style={styles.benefitIconText}>{icon}</Text>
      </View>

      <View>
        <Text style={styles.benefitTitle}>{title}</Text>
        <Text style={styles.benefitSubtitle}>{subtitle}</Text>
      </View>
    </View>
  );
}

/* ===============================================================
   CHECK CARD
================================================================ */

function CheckCard({
  icon,
  title,
  description,
}: {
  icon: string;
  title: string;
  description: string;
}) {
  return (
    <View style={styles.checkCard}>
      <View style={styles.checkIconCircle}>
        <Text style={styles.checkIconText}>{icon}</Text>
      </View>

      <View style={styles.checkContent}>
        <Text style={styles.checkTitle}>{title}</Text>

        <Text style={styles.checkDescription}>{description}</Text>
      </View>

      <Text style={styles.checkArrow}>›</Text>
    </View>
  );
}

/* ===============================================================
   STYLES
================================================================ */

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: COLORS.background,
  },

  scrollContent: {
    paddingHorizontal: 20,
    paddingTop: 12,
    paddingBottom: 34,
  },

  /* ---------------- HEADER ---------------- */

  header: {
    flexDirection: "row",
    justifyContent: "space-between",
    alignItems: "flex-start",
    marginBottom: 30,
  },

  brandRow: {
    flexDirection: "row",
    alignItems: "center",
  },

  logoMark: {
    width: 48,
    height: 48,
    borderRadius: 14,
    backgroundColor: COLORS.black,
    justifyContent: "center",
    alignItems: "center",
    position: "relative",
  },

  logoEnvelope: {
    width: 27,
    height: 20,
    borderWidth: 2,
    borderColor: COLORS.white,
    borderRadius: 4,
  },

  logoEnvelopeLineLeft: {
    position: "absolute",
    left: 3,
    top: 3,
    width: 12,
    height: 2,
    backgroundColor: COLORS.white,
    transform: [{ rotate: "34deg" }],
  },

  logoEnvelopeLineRight: {
    position: "absolute",
    right: 3,
    top: 3,
    width: 12,
    height: 2,
    backgroundColor: COLORS.white,
    transform: [{ rotate: "-34deg" }],
  },

  logoDot: {
    position: "absolute",
    width: 7,
    height: 7,
    borderRadius: 4,
    backgroundColor: "#4D9D72",
    right: 7,
    top: 8,
  },

  brandTextWrap: {
    marginLeft: 11,
  },

  brandName: {
    color: COLORS.black,
    fontSize: 20,
    fontWeight: "800",
    letterSpacing: -0.5,
  },

  brandAi: {
    fontWeight: "500",
  },

  brandTagline: {
    color: COLORS.muted,
    fontSize: 8,
    letterSpacing: 2.6,
    marginTop: 5,
  },

  statusPill: {
    flexDirection: "row",
    alignItems: "center",
    paddingHorizontal: 12,
    paddingVertical: 9,
    borderRadius: 18,
    backgroundColor: "#ECEAE4",
  },

  statusDot: {
    width: 9,
    height: 9,
    borderRadius: 5,
    backgroundColor: COLORS.success,
    marginRight: 8,
  },

  statusTitle: {
    color: COLORS.black,
    fontSize: 11,
    fontWeight: "700",
  },

  statusSubtitle: {
    color: COLORS.muted,
    fontSize: 9,
    marginTop: 2,
  },

  /* ---------------- HERO ---------------- */

  hero: {
    position: "relative",
  },

  eyebrow: {
    alignSelf: "flex-start",
    backgroundColor: COLORS.light,
    borderRadius: 20,
    paddingHorizontal: 14,
    paddingVertical: 9,
    marginBottom: 18,
  },

  eyebrowText: {
    color: COLORS.black,
    fontSize: 10,
    fontWeight: "700",
    letterSpacing: 2.1,
  },

  heroTitle: {
    color: COLORS.black,
    fontSize: 43,
    lineHeight: 46,
    fontWeight: "800",
    letterSpacing: -1.8,
    maxWidth: 350,
  },

  heroDescription: {
    color: "#575757",
    fontSize: 16,
    lineHeight: 25,
    marginTop: 18,
    maxWidth: 350,
  },

  securityIllustration: {
    height: 240,
    marginTop: 4,
    position: "relative",
  },

  illustrationRingOuter: {
    position: "absolute",
    width: 210,
    height: 210,
    borderRadius: 105,
    borderWidth: 1,
    borderColor: "#D9D6CE",
    right: 15,
    top: 10,
  },

  illustrationRingMiddle: {
    position: "absolute",
    width: 162,
    height: 162,
    borderRadius: 81,
    borderWidth: 1,
    borderColor: "#E1DED7",
    right: 39,
    top: 34,
  },

  illustrationCardBack: {
    position: "absolute",
    width: 150,
    height: 112,
    borderRadius: 18,
    backgroundColor: "#ECEAE4",
    right: 42,
    top: 58,
    transform: [{ rotate: "8deg" }],
  },

  illustrationCard: {
    position: "absolute",
    width: 145,
    height: 108,
    borderRadius: 18,
    backgroundColor: COLORS.white,
    right: 50,
    top: 48,
    borderWidth: 1,
    borderColor: "#E4E1D9",
    alignItems: "center",
    justifyContent: "center",
  },

  mailIcon: {
    width: 78,
    height: 58,
    borderWidth: 2,
    borderColor: COLORS.black,
    borderRadius: 8,
    justifyContent: "center",
    alignItems: "center",
    position: "relative",
  },

  mailTopLeft: {
    position: "absolute",
    width: 42,
    height: 2,
    backgroundColor: COLORS.black,
    transform: [{ rotate: "32deg" }],
    left: 3,
    top: 14,
  },

  mailTopRight: {
    position: "absolute",
    width: 42,
    height: 2,
    backgroundColor: COLORS.black,
    transform: [{ rotate: "-32deg" }],
    right: 3,
    top: 14,
  },

  mailG: {
    fontSize: 21,
    fontWeight: "800",
    color: COLORS.black,
  },

  signal: {
    position: "absolute",
    backgroundColor: COLORS.white,
    borderRadius: 18,
    borderWidth: 1,
    borderColor: "#E5E1D9",
    paddingHorizontal: 12,
    paddingVertical: 9,
    flexDirection: "row",
    alignItems: "center",
  },

  signalTop: {
    right: 42,
    top: 3,
  },

  signalRight: {
    right: 0,
    top: 94,
  },

  signalBottom: {
    left: 18,
    bottom: 20,
  },

  signalIcon: {
    fontSize: 15,
    fontWeight: "700",
    color: COLORS.black,
    marginRight: 7,
  },

  signalText: {
    fontSize: 11,
    lineHeight: 14,
    color: COLORS.black,
    fontWeight: "600",
  },

  illustrationArrow: {
    position: "absolute",
    right: 34,
    bottom: 2,
    alignItems: "center",
  },

  illustrationArrowText: {
    fontSize: 31,
    color: COLORS.black,
    transform: [{ rotate: "-35deg" }],
  },

  illustrationNote: {
    color: COLORS.black,
    fontSize: 11,
    lineHeight: 15,
    fontStyle: "italic",
    textAlign: "center",
    transform: [{ rotate: "-8deg" }],
    marginTop: -3,
  },

  /* ---------------- BENEFITS ---------------- */

  benefitsRow: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "space-between",
    marginTop: 2,
    marginBottom: 28,
  },

  benefit: {
    flexDirection: "row",
    alignItems: "center",
    flex: 1,
  },

  benefitIcon: {
    width: 30,
    height: 30,
    borderRadius: 15,
    backgroundColor: COLORS.light,
    alignItems: "center",
    justifyContent: "center",
    marginRight: 7,
  },

  benefitIconText: {
    color: COLORS.black,
    fontSize: 14,
    fontWeight: "700",
  },

  benefitTitle: {
    color: COLORS.black,
    fontSize: 10,
    fontWeight: "700",
  },

  benefitSubtitle: {
    color: COLORS.muted,
    fontSize: 10,
    marginTop: 2,
  },

  benefitDivider: {
    width: 1,
    height: 33,
    backgroundColor: COLORS.border,
    marginHorizontal: 6,
  },

  /* ---------------- GMAIL ---------------- */

  gmailCard: {
    minHeight: 120,
    borderRadius: 24,
    backgroundColor: COLORS.dark,
    padding: 18,
    flexDirection: "row",
    alignItems: "center",
  },

  gmailCardPressed: {
    opacity: 0.86,
    transform: [{ scale: 0.99 }],
  },

  gmailLogoBox: {
    width: 64,
    height: 64,
    borderRadius: 16,
    backgroundColor: COLORS.white,
    alignItems: "center",
    justifyContent: "center",
    marginRight: 15,
  },

  gmailLogoRed: {
    fontSize: 28,
    fontWeight: "900",
    color: "#D64545",
  },

  gmailContent: {
    flex: 1,
  },

  gmailTitle: {
    color: COLORS.white,
    fontSize: 20,
    fontWeight: "800",
    marginBottom: 6,
  },

  gmailSubtitle: {
    color: "#C3C3C3",
    fontSize: 12,
    lineHeight: 18,
  },

  gmailArrow: {
    width: 48,
    height: 48,
    borderRadius: 24,
    backgroundColor: COLORS.white,
    alignItems: "center",
    justifyContent: "center",
    marginLeft: 8,
  },

  gmailArrowText: {
    color: COLORS.black,
    fontSize: 26,
    fontWeight: "500",
  },

  /* ---------------- SECURITY NOTE ---------------- */

  securityNote: {
    marginTop: 18,
    borderRadius: 22,
    backgroundColor: "#FBFAF7",
    borderWidth: 1,
    borderColor: COLORS.border,
    minHeight: 78,
    paddingHorizontal: 14,
    paddingVertical: 14,
    flexDirection: "row",
    alignItems: "center",
  },

  lockCircle: {
    width: 38,
    height: 38,
    borderRadius: 19,
    backgroundColor: COLORS.light,
    alignItems: "center",
    justifyContent: "center",
    marginRight: 11,
  },

  lockIcon: {
    color: COLORS.black,
    fontSize: 18,
  },

  securityNoteText: {
    color: "#555555",
    fontSize: 11,
    lineHeight: 17,
    flex: 1,
  },

  infoCircle: {
    width: 22,
    height: 22,
    borderRadius: 11,
    borderWidth: 1,
    borderColor: COLORS.black,
    alignItems: "center",
    justifyContent: "center",
    marginLeft: 10,
  },

  infoText: {
    color: COLORS.black,
    fontSize: 12,
    fontWeight: "700",
  },

  /* ---------------- CHECKS ---------------- */

  sectionHeader: {
    flexDirection: "row",
    alignItems: "center",
    marginTop: 30,
    marginBottom: 14,
  },

  sectionTitle: {
    color: COLORS.black,
    fontSize: 20,
    fontWeight: "800",
    letterSpacing: -0.5,
  },

  sectionLine: {
    flex: 1,
    height: 1,
    backgroundColor: COLORS.border,
    marginLeft: 10,
  },

  sectionCaption: {
    color: COLORS.softMuted,
    fontSize: 7,
    letterSpacing: 1.3,
    marginLeft: 10,
  },

  checkGrid: {
    flexDirection: "row",
    flexWrap: "wrap",
    justifyContent: "space-between",
    gap: 10,
  },

  checkCard: {
    width: "48.3%",
    minHeight: 124,
    borderRadius: 20,
    backgroundColor: COLORS.surface,
    borderWidth: 1,
    borderColor: COLORS.border,
    padding: 13,
    position: "relative",
  },

  checkIconCircle: {
    width: 38,
    height: 38,
    borderRadius: 19,
    backgroundColor: COLORS.light,
    alignItems: "center",
    justifyContent: "center",
    marginBottom: 9,
  },

  checkIconText: {
    color: COLORS.black,
    fontSize: 16,
    fontWeight: "700",
  },

  checkContent: {
    paddingRight: 15,
  },

  checkTitle: {
    color: COLORS.black,
    fontSize: 13,
    fontWeight: "800",
    marginBottom: 5,
  },

  checkDescription: {
    color: COLORS.muted,
    fontSize: 10.5,
    lineHeight: 15,
  },

  checkArrow: {
    position: "absolute",
    right: 11,
    bottom: 11,
    color: COLORS.softMuted,
    fontSize: 23,
  },

  /* ---------------- BANNER ---------------- */

  brandBanner: {
    marginTop: 26,
    minHeight: 150,
    borderRadius: 22,
    backgroundColor: "#ECE9E1",
    borderWidth: 1,
    borderColor: COLORS.border,
    overflow: "hidden",
    position: "relative",
    padding: 20,
    justifyContent: "center",
  },

  bannerTextWrap: {
    zIndex: 3,
  },

  bannerLine: {
    color: COLORS.black,
    fontSize: 11,
    letterSpacing: 2.3,
    lineHeight: 21,
    fontWeight: "600",
  },

  bannerGraphic: {
    position: "absolute",
    right: -5,
    bottom: -1,
    width: 190,
    height: 115,
  },

  mountainOne: {
    position: "absolute",
    bottom: 0,
    right: 0,
    width: 150,
    height: 76,
    backgroundColor: "#D6D2C9",
    transform: [{ rotate: "-15deg" }],
  },

  mountainTwo: {
    position: "absolute",
    bottom: -1,
    right: 48,
    width: 104,
    height: 62,
    backgroundColor: "#C3BFB6",
    transform: [{ rotate: "21deg" }],
  },

  mountainThree: {
    position: "absolute",
    bottom: -1,
    right: 94,
    width: 80,
    height: 44,
    backgroundColor: "#AAA69D",
    transform: [{ rotate: "-22deg" }],
  },

  /* ---------------- FOOTER ---------------- */

  footer: {
    flexDirection: "row",
    alignItems: "center",
    justifyContent: "center",
    flexWrap: "wrap",
    marginTop: 22,
    paddingBottom: 4,
  },

  footerText: {
    color: COLORS.muted,
    fontSize: 8,
    letterSpacing: 1.7,
  },

  footerDivider: {
    color: COLORS.muted,
    marginHorizontal: 7,
    fontSize: 9,
  },

  indiaFlag: {
    fontSize: 11,
    marginLeft: 5,
  },
});