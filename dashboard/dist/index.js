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
 * The raw pairing capability lives only in the create-offer response and only
 * inside the QR image; it is never stored by this page or shown as text.
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

  function MercuryRelayPage() {
    var offerState = useState(null);
    var offer = offerState[0];
    var setOffer = offerState[1];
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

    var refresh = useCallback(function () {
      Promise.all([authed("/devices", {}), authed("/diagnostics", {})])
        .then(function (r) {
          setDevices((r[0] && r[0].devices) || []);
          setDiag(r[1]);
        })
        .catch(function (e) {
          setErr(e.message);
        });
    }, []);

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
                h("div", { className: "mr-muted", style: { marginTop: "10px" } },
                  "This QR contains the one-time pairing secret. It is shown once and " +
                    "is never stored or displayed as text."),
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
                  h("div", { className: "mr-fingerprint" }, d.fingerprint),
                  h("span", { className: "mr-pill mr-ok" }, "authorized")),
                h("button",
                  { className: "mr-btn mr-danger", onClick: function () { act(d, "revoke"); } },
                  "Revoke"),
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
    );
  }

  if (window.__HERMES_PLUGINS__ && typeof window.__HERMES_PLUGINS__.register === "function") {
    window.__HERMES_PLUGINS__.register("mercury-relay", MercuryRelayPage);
  }
})();
