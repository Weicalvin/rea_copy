import { readFile } from "node:fs/promises";
import { describe, expect, it, vi } from "vitest";

import {
  createApkAnalysisHttpHandler,
  summarizeManifest,
} from "../../../src/main/apkAnalysisHttp.js";

const apkBlob = (bytes = [0x50, 0x4b, 0x03, 0x04, 1, 2, 3, 4]) =>
  new Blob([new Uint8Array(bytes)], {
    type: "application/vnd.android.package-archive",
  });

const requestWith = (options: {
  fileName?: string;
  includeFile?: boolean;
  question?: string;
  bytes?: number[];
} = {}) => {
  const form = new FormData();
  if (options.includeFile !== false)
    form.append("file", apkBlob(options.bytes), options.fileName ?? "sample.apk");
  if (options.question !== undefined)
    form.append("question", options.question);
  return new Request("http://localhost/api/analyze-apk", {
    method: "POST",
    body: form,
  });
};

describe("APK analysis HTTP handler", () => {
  it("parses streamed upload, passes bounded metadata and question to Groq, and returns the answer", async () => {
    let uploadedBytes: Buffer | undefined;
    const parseManifest = vi.fn(async (filePath: string) => {
      uploadedBytes = await readFile(filePath);
      return {
        package: "org.example.demo",
        versionName: "1.4.2",
        versionCode: 14,
        usesSdk: { minSdkVersion: 23, targetSdkVersion: 35 },
        usesPermissions: [
          "android.permission.INTERNET",
          { name: "android.permission.CAMERA" },
        ],
        application: {
          debuggable: false,
          allowBackup: true,
          activities: [{ name: ".MainActivity", exported: true }],
        },
      };
    });
    const complete = vi.fn(async ({ question, manifest }) => {
      expect(question).toBe("這個 App 要求哪些敏感權限？");
      expect(manifest.packageName).toBe("org.example.demo");
      return "此 APK 要求網路與相機權限。";
    });
    const handler = createApkAnalysisHttpHandler({
      environment: {},
      parseManifest,
      complete,
    });

    const response = await handler(
      requestWith({ question: "這個 App 要求哪些敏感權限？" }),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      analysis: "此 APK 要求網路與相機權限。",
      apk: {
        fileName: "sample.apk",
        packageName: "org.example.demo",
        versionName: "1.4.2",
        versionCode: 14,
        minSdkVersion: 23,
        targetSdkVersion: 35,
        permissions: [
          "android.permission.INTERNET",
          "android.permission.CAMERA",
        ],
      },
    });
    expect(uploadedBytes).toEqual(Buffer.from([0x50, 0x4b, 3, 4, 1, 2, 3, 4]));
    expect(parseManifest).toHaveBeenCalledTimes(1);
    expect(complete).toHaveBeenCalledTimes(1);
  });

  it("rejects non-APK filenames and missing custom questions", async () => {
    const handler = createApkAnalysisHttpHandler({
      environment: {},
      parseManifest: vi.fn(async () => ({})),
      complete: vi.fn(async () => "unused"),
    });
    const invalidName = await handler(
      requestWith({ fileName: "sample.zip", question: "分析" }),
    );
    expect(invalidName.status).toBe(415);
    expect((await invalidName.json()) as { error: string }).toHaveProperty(
      "error",
      "apk_extension_required",
    );

    const missingQuestion = await handler(requestWith());
    expect(missingQuestion.status).toBe(400);
    expect((await missingQuestion.json()) as { error: string }).toHaveProperty(
      "error",
      "question_required",
    );
  });

  it("enforces the configured upload-size limit before manifest parsing", async () => {
    const parseManifest = vi.fn(async () => ({}));
    const handler = createApkAnalysisHttpHandler({
      environment: {},
      parseManifest,
      complete: vi.fn(async () => "unused"),
      maxUploadBytes: 8,
    });
    const response = await handler(
      requestWith({
        question: "分析",
        bytes: [0x50, 0x4b, 3, 4, 1, 2, 3, 4, 5],
      }),
    );
    expect(response.status).toBe(413);
    expect((await response.json()) as { error: string }).toHaveProperty(
      "error",
      "apk_too_large",
    );
    expect(parseManifest).not.toHaveBeenCalled();
  });

  it("returns a configuration error when GROQ_API_KEY is absent", async () => {
    const parseManifest = vi.fn(async () => ({}));
    const handler = createApkAnalysisHttpHandler({
      environment: {},
      parseManifest,
    });
    const response = await handler(requestWith({ question: "分析" }));
    expect(response.status).toBe(503);
    expect((await response.json()) as { error: string }).toHaveProperty(
      "error",
      "groq_not_configured",
    );
    expect(parseManifest).not.toHaveBeenCalled();
  });

  it("normalizes only bounded manifest fields", () => {
    const result = summarizeManifest("a.apk", {
      package: "org.example",
      usesPermissions: [
        { name: "android.permission.INTERNET" },
        { name: "android.permission.INTERNET" },
      ],
      application: {
        activities: [
          {
            name: ".MainActivity",
            exported: true,
            unexpectedPayload: "not included",
          },
        ],
      },
      unexpectedPayload: "not included",
    });
    expect(result.packageName).toBe("org.example");
    expect(result.permissions).toEqual(["android.permission.INTERNET"]);
    expect(result.application.activities).toEqual([
      { name: ".MainActivity", exported: true },
    ]);
    expect(JSON.stringify(result)).not.toContain("unexpectedPayload");
  });
});
