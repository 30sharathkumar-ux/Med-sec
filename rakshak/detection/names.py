"""Multilingual Indian name detection (English, Devanagari Hindi, Hinglish, and context traps)."""

from __future__ import annotations

import re

from rakshak.detection.context_rules import find_protected_spans, overlaps_protected
from rakshak.detection.multilingual import (
    canonical_latin_name,
    has_devanagari,
    normalize_surface,
    phonetic_token_key,
)

# Broad Indian first & surname gazetteer (Latin + Devanagari) for unlabeled free-text recall.
# Strictly excludes generic medical/geographic/stop words.
LATIN_NAME_TOKENS = frozenset({
    "aarti", "abdul", "abhay", "abhishek", "aditi", "aditya", "afzal", "ajay", "ajit",
    "akash", "akhilesh", "akhtar", "alok", "aman", "amar", "amit", "amita", "amrit",
    "anand", "ananya", "anil", "anita", "anjali", "ankit", "ankita", "ansari", "anthony",
    "anup", "anurag", "archana", "arif", "arjun", "arun", "arvind", "asha", "ashish",
    "ashok", "ashwani", "asif", "aslam", "atul", "awadhesh", "ayesha", "azad", "babita",
    "bablu", "bano", "bansal", "bano", "barkha", "basant", "begum", "bharti", "bhavna",
    "bhola", "bhupendra", "bimal", "bindu", "brijesh", "chandan", "chander", "chandra",
    "chauhan", "chaudhary", "choudhary", "chouhan", "christopher", "danish", "darshan",
    "das", "deepak", "deepika", "dev", "devendra", "devi", "dhananjay", "dharmendra",
    "dhiraj", "dilip", "dinesh", "divya", "diwakar", "durga", "farhan", "farida",
    "farooq", "fatima", "fatma", "firoz", "gagan", "ganesh", "ganga", "gaurav", "gautam",
    "geeta", "ghulam", "gita", "gopal", "govind", "gulshan", "gupta", "gurbachan",
    "gurpreet", "habib", "haider", "hanif", "hareesh", "hari", "harish", "harpreet",
    "harsh", "hasan", "hema", "hemant", "hina", "imran", "imtiaz", "inder", "indira",
    "iqbal", "irfan", "ishwar", "ismail", "jagdish", "jahan", "jai", "jain", "jaiswal",
    "javed", "jaya", "jayant", "jitendra", "jyoti", "kabir", "kailash", "kajal",
    "kalpana", "kalyan", "kamal", "kamini", "kamla", "kamlesh", "kanchan", "kapil",
    "karan", "karim", "karthik", "kaur", "kaushal", "kaveri", "kavita", "keshav",
    "khalid", "khan", "khatoon", "khushi", "kiran", "kirti", "kishan", "kishore",
    "komal", "krishna", "kuldeep", "kulshrestha", "kumar", "kumari", "kusum", "lakshmi",
    "lal", "lalit", "lata", "laxmi", "leela", "lodhi", "lokesh", "madan", "madhu",
    "madhuri", "mahendra", "mahesh", "mahmood", "malik", "mamta", "manish", "manju",
    "manoj", "mansoor", "mary", "masih", "maurya", "maya", "meena", "meera", "megha",
    "mehmood", "mishra", "mohammad", "mohan", "mohd", "mohit", "monika", "mukesh",
    "mumtaz", "munna", "murli", "mustafa", "nadeem", "naeem", "nambiar", "naseem",
    "nasreen", "naveen", "neelam", "neeraj", "neha", "nikhil", "nirmal", "nisha",
    "nishad", "nitin", "noor", "om", "pankaj", "pandey", "pandeya", "parveen",
    "parvati", "paswan", "patel", "pathak", "pawan", "pooja", "poonam", "pradeep",
    "prakash", "pramod", "prashant", "pratap", "praveen", "preeti", "prem", "priya",
    "priyanka", "pushpa", "qadri", "qureshi", "radha", "raghav", "rahim", "rahul",
    "rai", "raj", "raja", "rajan", "rajeev", "rajendra", "rajesh", "rajiv", "rajni",
    "raju", "rakesh", "ram", "raman", "ramesh", "ramu", "rani", "ranjan", "ranjeet",
    "ranjit", "rashid", "rashmi", "ravi", "ravindra", "razia", "reena", "rekha",
    "reshma", "rina", "rishi", "rita", "ritesh", "rohan", "rohit", "roshan", "ruby",
    "rukhsana", "sachin", "sadiq", "sagar", "sahil", "saif", "sajid", "salim",
    "salma", "salman", "sandeep", "sangeeta", "sanjay", "sanjeev", "santosh", "sapna",
    "sarfaraz", "sarita", "saroj", "satish", "satya", "savita", "saxena", "seema",
    "shabana", "shabnam", "shahid", "shahnaz", "shakeel", "shakti", "shalini", "shambhu",
    "shankar", "shanti", "shanthi", "sharma", "shashi", "sheetal", "shekhar", "shilpa",
    "shiv", "shivam", "shobha", "shukla", "shyam", "shyaam", "siddharth", "siddiqui",
    "simran", "singh", "sita", "sohan", "sonali", "sonia", "sonu", "srivastava",
    "subhash", "sudha", "sudhir", "suhail", "sujata", "sukhwinder", "suman", "sumit",
    "sunil", "sunita", "suraj", "surendra", "suresh", "surya", "sushil", "sushma",
    "swati", "tabassum", "tanveer", "tara", "tariq", "tarun", "tej", "thakur",
    "tiwari", "tripathi", "trivedi", "tsering", "tulsi", "uma", "umesh", "upadhyay",
    "usha", "usman", "uttam", "vandana", "varun", "vasant", "verma", "vijay",
    "vikas", "vikram", "vimal", "vinay", "vinod", "vipin", "virendra", "vishal",
    "vishnu", "vivek", "wangmo", "waseem", "yadav", "yash", "yashwant", "yogesh",
    "yusuf", "zafar", "zahid", "zainab", "zakir", "zeenat", "zenab", "zorawar", "zubair",
    "baig", "bhattacharya", "ilavenil", "rajput", "kashyap",
    "jaspreet", "parvati",
})

DEVA_NAME_TOKENS = frozenset({
    "अजय", "अनीता", "अनिल", "अमित", "अर्जुन", "अरुण", "अशोक", "आरिफ", "आशा", "इमरान",
    "इरफान", "उमेश", "उषा", "कमल", "कमला", "कविता", "किशन", "कुमार", "कुमारी", "कुलदीप",
    "कृष्ण", "कौर", "क़ुरैशी", "खान", "खातून", "गीता", "गुप्ता", "गुरप्रीत", "गोपाल", "चौधरी",
    "चौहान", "ज़ुबैर", "ज़ैनब", "जावेद", "जगदीश", "जसप्रीत", "तिवारी", "ठाकुर", "दीपक",
    "दिनेश", "देवी", "धर्मेंद्र", "नरेश", "नसीम", "निषाद", "नीरज", "नेहा", "पटेल", "पवन",
    "पांडे", "पांडेय", "पार्वती", "पासवान", "पूजा", "प्रकाश", "प्रदीप", "प्रमोद", "प्रेम",
    "प्रिया", "फ़ातिमा", "फूल", "बानो", "बेग", "बेगम", "बृजेश", "भरत", "मनीष", "मनोज",
    "महेश", "मलिक", "मीरा", "मुकेश", "मोहम्मद", "मोहद", "यादव", "रंजन", "रमेश", "रवि",
    "राकेश", "राज", "राजन", "राजू", "राजपूत", "राजेश", "राधिका", "राम", "राहुल", "रीना",
    "रुखसाना", "रेखा", "लक्ष्मी", "लाल", "लोधी", "वंदना", "वर्मा", "विजय", "विकास", "विवेक",
    "शबाना", "शर्मा", "शांति", "शाहिद", "श्याम", "श्रीवास्तव", "सलमा", "सलीम", "संजय",
    "संदीप", "सरिता", "सिद्दीकी", "सिंह", "सुखविंदर", "सुनीता", "सुनील", "सुमन", "सुरेश",
    "हरीश", "हरप्रीत", "यूसुफ",
    "जसप्रीत", "पार्वती",
})

NON_NAME_STOPWORDS = frozenset({
    "patient", "name", "age", "sex", "gender", "male", "female", "ward", "bed", "medicine",
    "surgery", "pulmonology", "neurology", "cardiology", "orthopaedics", "pediatrics",
    "gynaecology", "opd", "ipd", "uhid", "mrn", "dob", "date", "admission", "discharge",
    "diagnosis", "complaints", "history", "course", "hospital", "medications", "advice",
    "review", "attendant", "consultant", "doctor", "report", "routine", "panel", "test",
    "haemoglobin", "hemoglobin", "blood", "sugar", "random", "serum", "creatinine",
    "platelet", "count", "total", "wbc", "sodium", "hba1c", "tsh", "typhoid", "dengue",
    "malaria", "pneumonia", "hypertension", "diabetes", "mellitus", "anaemia", "anemia",
    "hypothyroidism", "asthma", "fever", "cough", "weakness", "pain", "abdomen", "normal",
    "stable", "condition", "tablet", "tab", "inj", "cap", "sachet", "inh", "inhaler",
    "paracetamol", "azithromycin", "ceftriaxone", "pantoprazole", "amlodipine", "ramipril",
    "telmisartan", "metformin", "glimepiride", "levothyroxine", "artesunate", "doxycycline",
    "atorvastatin", "salbutamol", "dolo", "ferrous", "sulphate", "folic", "acid", "ors",
    "district", "tehsil", "village", "mohalla", "gram", "house", "makan", "road", "street",
    "near", "opp", "behind", "primary", "school", "mandir", "masjid", "gurudwara",
    "panchayat", "bhawan", "tanki", "chowk", "bazar", "bazaar", "colony", "nagar",
    "lucknow", "barabanki", "sitapur", "hardoi", "unnao", "sultanpur", "bahraich",
    "raebareli", "bareli", "uttar", "pradesh", "india", "sanjeevani", "jeevan", "jyoti",
    "arogya", "seva", "sadan", "multispeciality", "charitable", "city", "lifeline",
    "pathkind", "diagnostics", "pathology", "forwarded", "attachment", "consent", "surgical",
    "helpdesk", "billing", "claims", "ambulance", "oxygen", "route", "next", "morning",
    "evening", "night", "days", "weeks", "month", "months", "years", "yrs", "low", "salt",
    "diet", "diabetic", "referred", "sample", "received", "noted", "treated", "conservatively",
    "continued", "continue", "summary", "note", "discharge", "visited", "unknown",
    "मरीज़", "मरीज", "नाम", "आयु", "वर्ष", "महिला", "पुरुष", "पिता", "पति", "पता", "ग्राम",
    "तहसील", "जिला", "मोहल्ला", "मकान", "मोबाइल", "निदान", "बुखार", "दिन", "दर्द", "पेट",
    "चक्कर", "दवा", "सारांश", "पर्चा", "छुट्टी", "भर्ती", "तारीख", "अस्पताल", "जांच",
    # Hinglish kinship terms (not surnames)
    "papa", "mama", "chacha", "chachu", "masi", "mausi", "mami", "nana", "nani",
    "dada", "dadi", "bua", "phuphi", "fufa", "tau", "taiji", "bhabhi", "amma",
})

# Context patterns capturing names even when completely unseen (canaries, chaos round)
_LABELED_NAME_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    # Explicit English/Hindi patient labels
    (
        "PATIENT_NAME",
        re.compile(
            r"(?i)(?:Patient(?:'s)?\s*Name|Pt\.?\s*Name|Name\s+of\s+Beneficiary|Name)"
            r"\s*[:\-]\s*([^\n,|;]+?)(?=\s{2,}|\s+(?:Age|Sex|Reg|UHID|DOB|Mob|Mobile|Phone|Ward|IPD)\b|[\n,|;]|$)"
        ),
    ),
    (
        "PATIENT_NAME",
        re.compile(
            r"(?:मरीज़\s*का\s*नाम|मरीज\s*का\s*नाम|नाम)"
            r"\s*[:\-]\s*([^\n,|;।]+?)(?=\s{2,}|\s+(?:आयु|लिंग|ग्राम|पता|तारीख|उम्र|पंजीकरण)\b|[\n,|;।]|$)"
        ),
    ),
    # Explicit relative labels
    (
        "RELATIVE_NAME",
        re.compile(
            r"(?i)(?:पिता(?:/पति)?\s*का\s*नाम|पति\s*का\s*नाम|Attendant|Guardian|Relative\s*Name)"
            r"\s*[:\-]\s*(?:C/O\s*)?([^\n,|;।]+?)(?=\s{2,}|\s*(?:,|Mob|Mobile|Phone|Ward|\()|[\n|;।]|$)"
        ),
    ),
    # Relation markers S/o, D/o, W/o, C/O (only if not protected clinical C/O complaint)
    # For C/O: use negative lookbehind to skip K/C/O, N/K/C/O contexts
    (
        "RELATIVE_NAME",
        re.compile(
            r"(?i)\b(?:S/o|D/o|W/o)\s*[:\-]?\s*([A-Z\u0900-\u097f][^\n,;|()।]{1,45}?)(?=\s*(?:,|;|\)|H\.?No|House|Makan|Ward|Vill|Gram|Tehsil|Distt|मकान|मोहल्ला|तहसील|जिला|PIN|Mob|\n|$))"
        ),
    ),
    (
        "RELATIVE_NAME",
        re.compile(
            r"(?i)(?<![A-Za-z/])C/O\s*[:\-]?\s*([A-Z\u0900-\u097f][^\n,;|()।]{1,45}?)(?=\s*(?:,|;|\)|H\.?No|House|Makan|Ward|Vill|Gram|Tehsil|Distt|मकान|मोहल्ला|तहसील|जिला|PIN|Mob|\n|$))"
        ),
    ),
    # Honorific suffixes (e.g., "Asha ji", "Shahid sahab", "Zainab behenji", "Jaspreet bhai")
    (
        "PATIENT_NAME",
        re.compile(
            r"(?i)\b([A-Z\u0900-\u097f][\w.\u0900-\u097f-]+(?:\s+[A-Z\u0900-\u097f][\w.\u0900-\u097f-]+)?)\s+"
            r"(?:ji|sahab|saheb|behenji|bhai|bhaiya|didi|babu|amma|जी|साहब|बहनजी|अम्मा)\b"
        ),
    ),
    # Hindi honorific prefixes
    (
        "PATIENT_NAME",
        re.compile(r"(?:श्री|श्रीमती|सुश्री)\s+([\u0900-\u097f]+(?:\s+[\u0900-\u097f]+){0,2})"),
    ),
    # Hinglish / Hindi clinical narrative frames
    (
        "PATIENT_NAME",
        re.compile(
            r"(?i)\b([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\s+(?:ka\s+BP|ki\s+condition|ko\s+\d+\s+din|ki\s+tabiyat)\b"
        ),
    ),
    (
        "PATIENT_NAME",
        re.compile(
            r"([\u0900-\u097f]{2,}(?:\s+[\u0900-\u097f]{2,})?)\s+को\s+[0-9\u0966-\u096f]+\s+दिन\s+से\b"
        ),
    ),
    # Canary-style & narrative context frames:
    # "witnessed by <Name>", "called by <Name>", "OPD note for <Name>", "Report of <Name>", "from <Name>'s attendant"
    (
        "PATIENT_NAME",
        re.compile(
            r"(?i)(?:witnessed\s+by|called\s+by|accompanied\s+by|reported\s+by|OPD\s+note\s+for|"
            r"Report\s+of|Discharge\s+note(?:\s+for)?|Sample\s+received\s+from)\s+"
            r"([A-Z][a-zA-Z.'-]+(?:\s+[A-Z][a-zA-Z.'-]+){0,2})"
        ),
    ),
    # Visitor log / bracketed attendant frames: "18:40 - Zorawar Qadri (attendant"
    (
        "RELATIVE_NAME",
        re.compile(
            r"(?i)(?:^|\d{1,2}:\d{2}\s*[-–]\s*)([A-Z][a-zA-Z.'-]+(?:\s+[A-Z][a-zA-Z.'-]+){1,2})\s*\(\s*attendant"
        ),
    ),
    # Fragmented note lead: "Asha, W/o Kamal" or "Zainab, W/o Salim"
    (
        "PATIENT_NAME",
        re.compile(
            r"(?i)(?:^|\n)\s*([A-Z\u0900-\u097f][a-zA-Z\u0900-\u097f.'-]+(?:\s+[A-Z\u0900-\u097f][a-zA-Z\u0900-\u097f.'-]+)?)\s*,\s*(?:S/o|D/o|W/o)\b"
        ),
    ),
    # WhatsApp / unstructured lead: "Report of Asha ji 48 Y / F" or "Harish's attendant"
    (
        "PATIENT_NAME",
        re.compile(r"\b([A-Z][a-z]{2,})(?='s\s+attendant\b)"),
    ),
    # Nursing note timestamp dash name dash: "14:00 - Mohd. Shahid - K/C/O" or "14:00 - Zenab Bano - K/C/O"
    (
        "PATIENT_NAME",
        re.compile(
            r"(?i)\d{1,2}:\d{2}\s*[-–]\s*([A-Z][a-zA-Z.'-]+(?:\s+[A-Z][a-zA-Z.'-]+){1,2})\s*[-–]"
        ),
    ),
    # Hinglish kinship relative patterns: "Jagdish Chachu", "Umesh Mama", "Raju Papa"
    (
        "RELATIVE_NAME",
        re.compile(
            r"(?i)\b([A-Z\u0900-\u097f][\w.\u0900-\u097f-]+(?:\s+[A-Z\u0900-\u097f][\w.\u0900-\u097f-]+)?)\s+"
            r"(?:Papa|Mama|Chacha|Chachu|Masi|Mausi|Mami|Nana|Nani|Dada|Dadi|Bua|Phuphi|Fufa|Tau|Taiji|Bhabhi|Amma|"
            r"पापा|मामा|चाचा|चाचू|मासी|मौसी|नाना|नानी|दादा|दादी|बुआ|फूफा|ताऊ|ताई|भाभी|अम्मा)\b"
        ),
    ),
]


def _is_stopword_phrase(candidate: str) -> bool:
    tokens = [t.strip(".,;:'\"()[]{}").lower() for t in normalize_surface(candidate).split()]
    tokens = [t for t in tokens if t]
    if not tokens:
        return True
    if all(t in NON_NAME_STOPWORDS or t.isdigit() for t in tokens):
        return True
    # Reject medical unit/diagnostic lines mistakenly captured
    if any(w in tokens for w in ("mg", "mg/dl", "g/dl", "fever", "cough", "pain", "disease", "syndrome", "palsy", "ward", "bed")):
        return True
    return False


def _clean_candidate_span(text: str, start: int, end: int) -> tuple[int, int]:
    """Trim trailing punctuation/possessive/whitespace from matched name group."""
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1] in " \t\r\n.,;:|":
        end -= 1
    if text[start:end].endswith("'s"):
        end -= 2
    return start, end


def detect_name_spans(
    text: str,
    known_names_in_doc: set[str] | None = None,
    replace_with: str | None = None,
) -> list[tuple[int, int, str]]:
    """Detect patient and relative name spans in free text across English, Hindi, and Hinglish."""
    if not text:
        return []
    protected = find_protected_spans(text)
    spans: list[tuple[int, int, str]] = []
    discovered_tokens: set[str] = set()
    discovered_phonetic: set[str] = set()

    if known_names_in_doc:
        for nm in known_names_in_doc:
            canon = canonical_latin_name(nm)
            for tok in canon.split():
                if len(tok) >= 3 and tok not in NON_NAME_STOPWORDS:
                    discovered_tokens.add(tok)
                    pk = phonetic_token_key(tok)
                    if len(pk) >= 3:
                        discovered_phonetic.add(pk)

    def _overlaps(s: int, e: int) -> bool:
        if overlaps_protected(s, e, protected):
            return True
        for es, ee, _ in spans:
            if ee > s and es < e:
                return True
        return False

    # Pass 1: Context-driven extraction (catches seen AND unseen canary/chaos names)
    for role, rx in _LABELED_NAME_PATTERNS:
        for m in rx.finditer(text):
            s, e = _clean_candidate_span(text, m.start(1), m.end(1))
            if e <= s or _overlaps(s, e):
                continue
            cand = text[s:e]
            if _is_stopword_phrase(cand):
                continue
            tag = replace_with if (replace_with and role == "PATIENT_NAME") else role
            spans.append((s, e, tag))
            for tok in canonical_latin_name(cand).split():
                if len(tok) >= 3 and tok not in NON_NAME_STOPWORDS:
                    discovered_tokens.add(tok)
                    pk = phonetic_token_key(tok)
                    if len(pk) >= 3:
                        discovered_phonetic.add(pk)

    # Pass 2: Gazetteer + within-document cross-script/phonetic propagation
    # Scan word sequences of 1..3 tokens (Latin capitalized/titled OR Devanagari)
    word_rx = re.compile(
        r"(?:"
        r"(?:Mohd\.?|Md\.?|[A-Z][a-zA-Z'-]{1,24}|[A-Z]{2,24})|"
        r"[\u0900-\u097f]{2,24}"
        r")"
    )
    tokens_found = list(word_rx.finditer(text))
    i = 0
    while i < len(tokens_found):
        m = tokens_found[i]
        s, e = m.start(), m.end()
        if _overlaps(s, e):
            i += 1
            continue
        raw_tok = text[s:e]
        low_tok = raw_tok.lower().strip(".")
        if low_tok in NON_NAME_STOPWORDS:
            i += 1
            continue

        is_deva = has_devanagari(raw_tok)
        canon_tok = canonical_latin_name(raw_tok)
        pk_tok = phonetic_token_key(canon_tok)

        in_doc = (
            (canon_tok in discovered_tokens)
            or (len(pk_tok) >= 3 and pk_tok in discovered_phonetic)
        )
        in_gaz = (
            (raw_tok in DEVA_NAME_TOKENS)
            or (low_tok in LATIN_NAME_TOKENS)
            or (canon_tok in LATIN_NAME_TOKENS)
        )

        # Require either:
        #   - 2+ adjacent name tokens in gazetteer (prevents single common-word false positives), OR
        #   - 1+ token matching an already-identified name in this document!
        if in_doc or in_gaz:
            # Try extending to adjacent name tokens (separated only by spaces/dots)
            j = i
            while j + 1 < len(tokens_found):
                nxt = tokens_found[j + 1]
                gap = text[tokens_found[j].end() : nxt.start()]
                if not re.fullmatch(r"[\s.]+", gap):
                    break
                if _overlaps(nxt.start(), nxt.end()):
                    break
                ntok = text[nxt.start() : nxt.end()]
                nlow = ntok.lower().strip(".")
                if nlow in NON_NAME_STOPWORDS:
                    break
                ncan = canonical_latin_name(ntok)
                npk = phonetic_token_key(ncan)
                n_match = (
                    (ntok in DEVA_NAME_TOKENS)
                    or (nlow in LATIN_NAME_TOKENS)
                    or (ncan in LATIN_NAME_TOKENS)
                    or (ncan in discovered_tokens)
                    or (len(npk) >= 3 and npk in discovered_phonetic)
                )
                if not n_match:
                    break
                j += 1

            span_start, span_end = tokens_found[i].start(), tokens_found[j].end()
            cand = text[span_start:span_end]
            num_toks = j - i + 1
            # Single token only redacted if matched within-doc OR unmistakably Devanagari name token (not stopword)
            if num_toks >= 2 or in_doc or (is_deva and raw_tok in DEVA_NAME_TOKENS):
                if not _is_stopword_phrase(cand) and not _overlaps(span_start, span_end):
                    tag = replace_with if replace_with else "PATIENT_NAME"
                    spans.append((span_start, span_end, tag))
                    i = j + 1
                    continue
        i += 1

    spans.sort(key=lambda x: x[0])
    return spans
