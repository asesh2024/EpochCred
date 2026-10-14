'use strict';
// Deterministic synthetic academic records (no real personal data). Seeded PRNG for reproducibility.
function mulberry32(seed) {
  return function () {
    seed |= 0; seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const FIRST = ['Aarav', 'Diya', 'Vihaan', 'Ananya', 'Arjun', 'Isha', 'Kabir', 'Meera', 'Rohan', 'Sneha', 'Aditya', 'Kavya', 'Rahul', 'Pooja', 'Sai', 'Lakshmi', 'Ravi', 'Divya', 'Karthik', 'Nandini'];
const LAST = ['Reddy', 'Sharma', 'Naidu', 'Iyer', 'Rao', 'Gupta', 'Varma', 'Patel', 'Menon', 'Chowdary', 'Kumar', 'Das', 'Pillai', 'Singh', 'Joshi'];
const PROGRAMS = [
  ['B.Tech', 'Computer Science and Engineering'], ['B.Tech', 'Electronics and Communication Engineering'],
  ['B.Tech', 'Mechanical Engineering'], ['B.Tech', 'Civil Engineering'], ['M.Tech', 'Data Science'],
  ['MBA', 'Finance'], ['B.Sc', 'Mathematics'], ['M.Sc', 'Physics'], ['BBA', 'Marketing'], ['Ph.D', 'Computer Science'],
];

function makeRecords(n, seed = 42, institution = 'Example Institute of Technology') {
  const rnd = mulberry32(seed);
  const pick = (a) => a[Math.floor(rnd() * a.length)];
  const out = [];
  for (let i = 0; i < n; i++) {
    const [degree, major] = pick(PROGRAMS);
    const adm = 2018 + Math.floor(rnd() * 5);
    const cgpa = (5 + rnd() * 5).toFixed(2);
    const y = 1998 + Math.floor(rnd() * 8), m = 1 + Math.floor(rnd() * 12), d = 1 + Math.floor(rnd() * 28);
    const name = `${pick(FIRST)} ${pick(LAST)}`;
    out.push({
      institution, studentName: name, studentId: `EIT${adm}${String(i).padStart(6, '0')}`,
      dateOfBirth: `${y}-${String(m).padStart(2, '0')}-${String(d).padStart(2, '0')}`,
      program: `${degree} ${major}`, degree, major, cgpa,
      classification: cgpa >= 8 ? 'First Class with Distinction' : cgpa >= 6.5 ? 'First Class' : 'Second Class',
      admissionYear: String(adm), graduationYear: String(adm + 4),
      transcriptHash: '0x' + Array.from({ length: 32 }, () => Math.floor(rnd() * 256).toString(16).padStart(2, '0')).join(''),
      issueDate: `${adm + 4}-07-15`, convocationNo: String(10 + (adm - 2018)), nationality: 'Indian',
      email: `${name.toLowerCase().replace(' ', '.')}${i}@example.edu`,
    });
  }
  return out;
}

module.exports = { makeRecords, mulberry32 };
