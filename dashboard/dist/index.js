/**
 * Mercury Relay — Dashboard management page.
 *
 * Plain IIFE, no build step. Renders the owner-facing pairing/approval/revoke
 * surface. All data calls go through SDK.authedFetch to the plugin's own
 * backend at /api/plugins/mercury-relay/*, which carries the dashboard's
 * authentication and base-path prefix — so this page works unchanged when a
 * Hermes Desktop on another machine points at this box as a remote gateway
 * (the Desktop loads this box's dashboard SPA and its plugin assets; nothing
 * runs on the Desktop side).
 *
 * The QR is rendered server-side (returned as an inline SVG in the create
 * response), so both this page and the desktop plugin show one identical QR.
 * The raw pairing capability lives only in the create-offer response: inside
 * the QR image, and behind a "Copy pairing code" button for phones whose
 * camera cannot read the QR. It is never stored by this page or shown as text.
 */
(function () {
  "use strict";

  var SDK = window.__HERMES_PLUGIN_SDK__;
  if (!SDK) return;
  var React = SDK.React;
  var h = React.createElement;
  var useState = React.useState;
  var useEffect = React.useEffect;
  var useCallback = React.useCallback;

  var API = "/api/plugins/mercury-relay";

  function authed(path, opts) {
    var fetcher = SDK.authedFetch || window.fetch;
    return fetcher(API + path, opts).then(function (resp) {
      var ct = resp.headers.get("content-type") || "";
      var body = ct.indexOf("json") >= 0 ? resp.json() : resp.text();
      return body.then(function (parsed) {
        if (!resp.ok) {
          var detail = parsed && parsed.detail ? parsed.detail : resp.status;
          throw new Error(String(detail));
        }
        return parsed;
      });
    });
  }

  function jsonBody(value) {
    return {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(value),
    };
  }

  function QrImage(props) {
    var ref = React.useRef(null);
    useEffect(
      function () {
        var host = ref.current;
        if (!host) return;
        // The SVG is generated server-side and returned in the create
        // response; render it directly (it contains no script).
        host.innerHTML = props.svg || "";
      },
      [props.svg],
    );
    return h("div", { className: "mr-qr", ref: ref });
  }

  // Copy text to the clipboard. The async Clipboard API needs a secure
  // context (https or localhost) and a user gesture; a dashboard reached
  // over plain http on the LAN has no navigator.clipboard, so fall back to
  // a transient textarea + execCommand. Resolves true when a copy happened.
  function copyText(text) {
    if (typeof text !== "string" || !text) return Promise.resolve(false);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text).then(
        function () { return true; },
        function () { return copyTextLegacy(text); },
      );
    }
    return Promise.resolve(copyTextLegacy(text));
  }

  function copyTextLegacy(text) {
    try {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand && document.execCommand("copy");
      document.body.removeChild(ta);
      return Boolean(ok);
    } catch (e) {
      return false;
    }
  }

  function Countdown(props) {
    var expiresAt = props.expiresAt;
    var tick = useState(0);
    var setTick = tick[1];
    useEffect(
      function () {
        var id = setInterval(function () {
          setTick(function (n) {
            return n + 1;
          });
        }, 1000);
        return function () {
          clearInterval(id);
        };
      },
      [],
    );
    var remaining = Math.max(0, expiresAt - Math.floor(Date.now() / 1000));
    var mm = Math.floor(remaining / 60);
    var ss = remaining % 60;
    return h(
      "span",
      { className: "mr-countdown" },
      remaining > 0 ? "expires in " + mm + ":" + (ss < 10 ? "0" + ss : ss) : "expired",
    );
  }

  function formatChecked(ts) {
    if (!ts) return "never";
    var age = Math.max(0, Math.floor(Date.now() / 1000 - ts));
    if (age < 60) return "just now";
    if (age < 3600) return Math.floor(age / 60) + " min ago";
    return Math.floor(age / 3600) + " h ago";
  }

  /** Small pulsing pill in the dashboard header while an update is available. */
  function UpdateBadge() {
    var state = useState(null);
    var update = state[0];
    var setUpdate = state[1];
    useEffect(
      function () {
        var cancelled = false;
        function poll() {
          authed("/update", {})
            .then(function (u) { if (!cancelled) setUpdate(u); })
            .catch(function () {});
        }
        poll();
        var id = setInterval(poll, 60000);
        return function () { cancelled = true; clearInterval(id); };
      },
      [],
    );
    if (!update || !update.available) return null;
    return h(
      "a",
      {
        className: "mr-update-badge",
        href: "/mercury-relay",
        title: "Mercury Relay " + update.latest + " is available (installed " + update.installed + ")",
        onClick: function (e) {
          e.preventDefault();
          window.history.pushState({}, "", "/mercury-relay");
          window.dispatchEvent(new PopStateEvent("popstate"));
        },
      },
      h("span", { className: "mr-update-dot" }),
      "Relay update " + update.latest,
    );
  }

  function UpdatesCard(props) {
    var u = props.update;
    var busy = props.busy;
    if (!u) return null;
    var canApply = u.install && u.install.kind === "git";
    return h(
      "div",
      { className: "mr-card" },
      h("div", { className: "mr-row mr-spread" },
        h("div", null,
          h("h2", null, "Updates"),
          h("div", { className: "mr-muted" },
            "Installed " + u.installed +
              (u.latest ? " · latest " + u.latest : "") +
              " · checked " + formatChecked(u.checked_at) +
              (u.enabled ? " · checks every 6 h" : " · automatic checks off") +
              (u.error ? " · last check failed" : "")),
          u.install && u.install.branch
            ? h("div", { className: "mr-muted mr-mono" }, u.install.branch + " @ " + (u.install.commit || ""))
            : null),
        h("div", { className: "mr-row" },
          h("button", { className: "mr-btn", onClick: props.onCheck, disabled: busy }, "Check now"),
          u.available
            ? h("button", { className: "mr-btn", onClick: props.onApply, disabled: busy || !canApply,
                title: canApply ? "" : "This install is not a git checkout; update it the way it was installed." },
                busy ? "Updating…" : "Update now")
            : null)),
      u.available
        ? h("div", { className: "mr-banner" },
            h("span", { className: "mr-update-dot" }),
            "Mercury Relay " + u.latest + " is available. Update now runs " +
              u.update_command + " through Hermes' plugin manager; restart the gateway afterwards.")
        : null,
      props.result
        ? h("div", { className: props.result.ok ? "mr-banner" : "mr-banner mr-error" },
            props.result.ok
              ? "Updated. Restart the Hermes gateway to load the new version."
              : "Update failed: " + (props.result.reason || "unknown") + ".",
            props.result.output
              ? h("pre", { className: "mr-output" }, props.result.output)
              : null)
        : null,
    );
  }

  function MercuryRelayPage() {
    var offerState = useState(null);
    var offer = offerState[0];
    var setOffer = offerState[1];
    var copiedState = useState(null);
    var copied = copiedState[0];
    var setCopied = copiedState[1];
    var devicesState = useState([]);
    var devices = devicesState[0];
    var setDevices = devicesState[1];
    var diagState = useState(null);
    var diag = diagState[0];
    var setDiag = diagState[1];
    var errState = useState(null);
    var err = errState[0];
    var setErr = errState[1];
    var busyState = useState(false);
    var busy = busyState[0];
    var setBusy = busyState[1];
    var updateState = useState(null);
    var update = updateState[0];
    var setUpdate = updateState[1];
    var updateBusyState = useState(false);
    var updateBusy = updateBusyState[0];
    var setUpdateBusy = updateBusyState[1];
    var updateResultState = useState(null);
    var updateResult = updateResultState[0];
    var setUpdateResult = updateResultState[1];

    var refresh = useCallback(function () {
      Promise.all([authed("/devices", {}), authed("/diagnostics", {}), authed("/update", {})])
        .then(function (r) {
          setDevices((r[0] && r[0].devices) || []);
          setDiag(r[1]);
          setUpdate(r[2]);
        })
        .catch(function (e) {
          setErr(e.message);
        });
    }, []);

    function checkUpdates() {
      setUpdateBusy(true);
      authed("/update/check", jsonBody({}))
        .then(setUpdate)
        .catch(function (e) { setErr(e.message); })
        .finally(function () { setUpdateBusy(false); });
    }

    function applyUpdate() {
      if (!window.confirm("Update the Mercury Relay plugin on this host now? Hermes will pull the latest release; you will need to restart the gateway afterwards.")) return;
      setUpdateBusy(true);
      setUpdateResult(null);
      authed("/update/apply", jsonBody({}))
        .then(function (r) { setUpdateResult(r); refresh(); })
        .catch(function (e) { setErr(e.message); })
        .finally(function () { setUpdateBusy(false); });
    }

    useEffect(
      function () {
        refresh();
        var id = setInterval(refresh, 4000);
        return function () {
          clearInterval(id);
        };
      },
      [refresh],
    );

    function createOffer() {
      setBusy(true);
      setErr(null);
      authed("/pairing-offers", jsonBody({}))
        .then(function (o) {
          setCopied(null);
          setOffer(o);
          refresh();
        })
        .catch(function (e) {
          setErr(e.message);
        })
        .finally(function () {
          setBusy(false);
        });
    }

    function approve(device) {
      if (
        !window.confirm(
          "Approve this device?\n\nConfirm the fingerprint below matches the one shown " +
            "on the phone:\n\n" +
            device.fingerprint,
        )
      ) {
        return;
      }
      authed(
        "/devices/" + encodeURIComponent(device.device_id) + "/approve",
        jsonBody({ confirmed_fingerprint: device.fingerprint }),
      )
        .then(refresh)
        .catch(function (e) {
          setErr(e.message);
        });
    }

    function rename(device) {
      var current = device.label || "";
      var next = window.prompt(
        "Nickname for this device (leave empty to use the phone's own name):",
        current,
      );
      if (next === null) return;
      authed(
        "/devices/" + encodeURIComponent(device.device_id) + "/label",
        jsonBody({ label: next.trim().slice(0, 64) }),
      )
        .then(refresh)
        .catch(function (e) {
          setErr(e.message);
        });
    }

    function deviceTitle(device) {
      return device.display_name || device.label || device.device_name || device.fingerprint;
    }

    function deviceSubtitle(device) {
      var parts = [];
      if (device.label && device.device_name && device.label !== device.device_name) {
        parts.push(device.device_name);
      }
      parts.push(device.fingerprint);
      return parts.join(" · ");
    }

    function act(device, verb) {
      authed("/devices/" + encodeURIComponent(device.device_id) + "/" + verb, jsonBody({}))
        .then(refresh)
        .catch(function (e) {
          setErr(e.message);
        });
    }

    var pending = devices.filter(function (d) {
      return d.status === "pending";
    });
    var authorized = devices.filter(function (d) {
      return d.status === "authorized";
    });
    var relayConfigured = diag && diag.relay_origin_configured;

    return h(
      "div",
      { className: "mr-page" },
      err
        ? h("div", { className: "mr-banner mr-error" }, "Error: " + err)
        : null,
      relayConfigured === false
        ? h(
            "div",
            { className: "mr-banner" },
            "No relay origin is configured yet. Pairing works, but the phone cannot " +
              "connect until the hosted relay origin is set in the plugin configuration.",
          )
        : null,

      // -- pairing ----------------------------------------------------------
      h(
        "div",
        { className: "mr-card" },
        h("div", { className: "mr-row mr-spread" },
          h("div", null,
            h("h2", null, "Pair a phone"),
            h("div", { className: "mr-muted" },
              "Generate a one-time QR, scan it in Mercury on the phone, then approve " +
                "the device after confirming the fingerprints match."),
          ),
          h("button", { className: "mr-btn", onClick: createOffer, disabled: busy },
            busy ? "Generating…" : offer ? "New QR" : "Generate QR"),
        ),
        offer
          ? h(
              "div",
              { className: "mr-qr-wrap", style: { marginTop: "16px" } },
              h(QrImage, { svg: offer.qr_svg }),
              h(
                "div",
                { style: { flex: "1", minWidth: "220px" } },
                h("div", { className: "mr-muted" }, "Offer "),
                h("div", { className: "mr-fingerprint" }, offer.offer_id),
                h("div", { className: "mr-muted", style: { marginTop: "10px" } },
                  h(Countdown, { expiresAt: offer.expires_at })),
                // Camera trouble (auto-zoom cropping the code, no camera at
                // all): the same payload the QR encodes can be copied and
                // pasted into Mercury. It is copied, never rendered as text.
                h("div", { className: "mr-row", style: { marginTop: "10px" } },
                  h("button", {
                    className: "mr-btn mr-ghost",
                    disabled: !offer.pairing_payload,
                    onClick: function () {
                      copyText(offer.pairing_payload).then(function (ok) {
                        setCopied(ok ? "copied" : "failed");
                        setTimeout(function () { setCopied(null); }, 2000);
                      });
                    },
                  }, copied === "copied" ? "Copied" : "Copy pairing code"),
                  copied === "failed"
                    ? h("span", { className: "mr-muted" }, "Clipboard unavailable")
                    : null),
                h("div", { className: "mr-muted", style: { marginTop: "10px" } },
                  "This QR contains the one-time pairing secret. Scan it, or copy the " +
                    "pairing code and paste it into Mercury if the camera cannot read " +
                    "the QR. It is shown once and never stored or displayed as text."),
              ),
            )
          : null,
      ),

      // -- pending approvals ------------------------------------------------
      pending.length > 0
        ? h(
            "div",
            { className: "mr-card" },
            h("h2", null, "Waiting for approval"),
            h("div", { className: "mr-muted" },
              "Confirm each fingerprint matches the phone before approving."),
            pending.map(function (d) {
              return h(
                "div",
                { className: "mr-device", key: d.device_id },
                h("div", null,
                  h("div", { className: "mr-name" }, deviceTitle(d)),
                  h("div", { className: "mr-fingerprint" }, d.fingerprint),
                  h("div", { className: "mr-muted" }, "pending")),
                h("div", { className: "mr-row" },
                  h("button", { className: "mr-btn", onClick: function () { approve(d); } },
                    "Approve"),
                  h("button",
                    { className: "mr-btn mr-danger", onClick: function () { act(d, "deny"); } },
                    "Deny")),
              );
            }),
          )
        : null,

      // -- authorized devices ----------------------------------------------
      h(
        "div",
        { className: "mr-card" },
        h("h2", null, "Devices"),
        authorized.length === 0
          ? h("div", { className: "mr-muted" }, "No authorized devices.")
          : authorized.map(function (d) {
              return h(
                "div",
                { className: "mr-device", key: d.device_id },
                h("div", null,
                  h("div", { className: "mr-name" }, deviceTitle(d)),
                  h("div", { className: "mr-muted mr-mono" }, deviceSubtitle(d)),
                  h("span", { className: "mr-pill mr-ok" }, "authorized")),
                h("div", { className: "mr-row" },
                  h("button", { className: "mr-btn", onClick: function () { rename(d); } },
                    "Rename"),
                  h("button",
                    { className: "mr-btn mr-danger", onClick: function () { act(d, "revoke"); } },
                    "Revoke")),
              );
            }),
      ),

      // -- status -----------------------------------------------------------
      diag
        ? h(
            "div",
            { className: "mr-card" },
            h("h2", null, "Status"),
            h("div", { className: "mr-muted" },
              "Runtime: " + (diag.runtime && diag.runtime.runtime) +
                " · active sessions: " + diag.active_leases +
                " · relay origin: " + (relayConfigured ? "configured" : "not set")),
          )
        : null,

      // -- relay access -----------------------------------------------------
      // The machine ID is a hash over this installation's relay route and its
      // routing issuer public key. It is not a secret and admits only this
      // installation; the relay operator allowlists it in the operations
      // console before the hosted relay accepts this gateway.
      diag && diag.relay_machine_id
        ? h(
            "div",
            { className: "mr-card" },
            h("h2", null, "Relay access"),
            h("div", { className: "mr-muted" },
              "Send this machine ID to the relay operator to allow this gateway " +
                "to connect to the hosted relay."),
            h("div", { className: "mr-row mr-spread", style: { marginTop: "10px" } },
              h("div", { className: "mr-fingerprint" }, diag.relay_machine_id),
              h("button", {
                className: "mr-btn mr-ghost",
                onClick: function () {
                  copyText(diag.relay_machine_id);
                },
              }, "Copy")),
          )
        : null,

      // -- updates (last) ---------------------------------------------------
      h(UpdatesCard, { update: update, busy: updateBusy, result: updateResult,
        onCheck: checkUpdates, onApply: applyUpdate }),
    );
  }

  if (window.__HERMES_PLUGINS__ && typeof window.__HERMES_PLUGINS__.register === "function") {
    window.__HERMES_PLUGINS__.register("mercury-relay", MercuryRelayPage);
    if (typeof window.__HERMES_PLUGINS__.registerSlot === "function") {
      // The sidebar tab has no badge API; the header slot is the closest
      // always-visible spot for "an update is waiting".
      window.__HERMES_PLUGINS__.registerSlot("header-right", "mercury-relay-update", UpdateBadge);
    }
  }
})();
