from google import genai
from .gemini_schema import AILogicGroup
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
from google import genai
from pydantic import BaseModel
from django.views import View


client = genai.Client(api_key="AIzaSyAJYEmM4pDiUWvJAw90nzAgEb81LfH9KcE")


# Define response schema
class SuggestedRuleSet(BaseModel):
    recipe_name: str
    description: str

@csrf_exempt
def generate_ruleset(request):
    if request.method == "POST":
        body = json.loads(request.body)
        prompt = body.get("description", "")

        client = genai.Client(api_key="YOUR_API_KEY")
        try:
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": SuggestedRuleSet,
                },
            )
            return JsonResponse(response.parsed.dict())
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)

def suggest_rules_from_log(log_text: str) -> AILogicGroup:
    prompt = [
        "You are a threat detection assistant. Given raw security log content, suggest a logical rule set to identify potential security issues.",
        "Use the nested logic structure (AND/OR). Each rule should have field, operator, value, severity, and optional tags.",
        f"Log content:\n{log_text[:1500]}..."  # truncate for safety
    ]

    response = client.generate_content(
        contents=[{"role": "user", "parts": prompt}],
        generation_config={
            "response_mime_type": "application/json",
            "response_schema": AILogicGroup
        }
    )
    return response.parsed
