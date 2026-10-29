# Three-minute video and submission guide

## Prepare

Follow the README to build and start the lab. Keep the dashboard open at http://127.0.0.1:8088/. Have the report, model card, and GitHub repository ready. Use the supplied fictional scenarios. The dashboard should say **Capture active** before generating traffic.

## Video outline

| Time | Show and explain |
| --- | --- |
| 0:00–0:25 | “This is CodeAlpha Task 4: a custom Python network IDS with our own rules and a Random Forest classifier. Scapy and scikit-learn supply library functions.” |
| 0:25–0:50 | Explain the isolated target, sensor sharing its interface, traffic generator, persistent incidents, and local dashboard. Show capture health and model version. |
| 0:50–1:20 | Run `docker compose run --rm traffic suspicious`. Point to the five rule signatures, source/target, severity, and investigation guidance. ICMP is informational. |
| 1:20–1:45 | Wait for window closure, then run `docker compose run --rm traffic burst`. Show the ML alert and its uncalibrated score. Explain that this is a supported demonstration pattern, distinct from evaluation. |
| 1:45–2:20 | Open the model card. Explain raw public PCAP feature extraction, frozen capture splits, and independent lab sessions. Show both held-out tables, the 15.4% public false-positive rate, and the majority baseline. |
| 2:20–2:45 | Show test results, live-verification evidence, and an exported incident summary. Explain continuous capture, rule/ML separation, and response records. |
| 2:45–3:00 | Link the public GitHub repository, report, and project ZIP. State the model's limitations and local educational scope. |

Use `docker compose logs -f sensor` to show console notifications; Ctrl+C exits the log viewer. Stop the lab afterwards with `docker compose down`, preserving its incident volume. Keep GitHub authentication, environment variables, and unrelated network data out of recordings.

## Suggested caption

“Completed CodeAlpha Cyber Security Task 4: a custom Network Intrusion Detection System using Python, Scapy, and machine learning. I built packet feature extraction, custom rules, a trained Random Forest, incident handling, and a live dashboard. The report includes held-out public/lab results, false positives, and reproducible tests.”

Repository: https://github.com/cedric-malfoy/CodeAlpha_NetworkIntrusionDetectionSystem

Tag CodeAlpha as required by the internship brief. Do not describe model scores as attack probabilities or present lab-only performance as universal accuracy.

## Submission checklist

- Open the public repository while signed out.
- Read the model card and run the lab yourself before explaining it.
- Publish your explanation video on LinkedIn, including the GitHub link and CodeAlpha tag.
- Keep the PDF report and project ZIP available for requested attachments.
- Submit the repository and video links through the official form shared in your internship WhatsApp group.
- Follow the actual form's deadline and fields; no form URL was included in the brief.

LinkedIn posting and internship submission are manual. The project does not post messages, send email, or submit forms.
