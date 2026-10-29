# Featured writer picks

`public/featured-writers.json` is the curated source for the Top 3 profiles shown by the Local/Beat Writers and Independent Writers source filters. Each list is ordered by FanOptic's editorial picks, not by popularity. The interface displays at most three profiles for the selected filter.

Add a profile only after confirming that it has a verified profile or publication page, publishes original reporting, has recent coverage relevant to the writer's team and sport, and contributes a distinct voice or outlet where possible. Review the lists periodically and remove or replace inactive writers.

Each profile should use this shape:

```json
{
  "name": "Writer name",
  "label": "Broncos beat writer",
  "team": "Denver Broncos",
  "league": "NFL",
  "profileUrl": "https://publisher.example/writer",
  "photoUrl": "https://publisher.example/writer-photo.jpg",
  "lastReviewedAt": "2026-10-29"
}
```

`photoUrl` may be omitted. Use the writer's actual photo only when available; otherwise the interface uses initials. Both the image and name link directly to `profileUrl`. Keep the registry empty until picks have been reviewed; do not add placeholder writers as if they were real people.
