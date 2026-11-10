# Feed filter behavior

## Feed mode

- **Latest** includes all fresh matching stories, ordered by publication date.
- **Analysis** includes stories whose headline or RSS description identifies analysis, opinion, breakdown, film study, scouting, grades, or rankings.
- **Game day** includes previews, live updates, recaps, scores, and game notes.
- **Rumors** is a separate mode. It requests team- and sport-specific rumor coverage and only includes items whose headline or RSS description contains an explicit rumor or speculation signal. Cards are labeled **Unconfirmed Rumor** and retain the publisher, author when supplied, publication time, and original-story link.

Rumor items are excluded when the headline or description indicates the report has been confirmed, denied, or otherwise resolved. The existing three-day article freshness limit removes stale items. Resolved follow-up stories can still appear in Latest.

## Source filter

The Sources dropdown is independent of Feed mode. It filters articles by the publisher classification: National, Local/Beat, Independent, Team/League, or All sources. The Independent Writers selection also asks the live search for coverage from independent sports publishers, then applies the normal team and sport checks. The independent publisher list and classifier are maintained in server.js; unrecognized publishers remain available under All sources.

## Team scope and Discovery

My Teams requests articles for the signed-in account's selected teams. The server checks the article against the selected team's name and sport before returning it. An empty team selection returns no team articles. Discovery uses league-wide queries and remains separate.

## Writer profiles

Up to three writer cards are shown only when Local/Beat Writers or Independent Writers is selected under Sources. Cards use reviewed profiles where available and otherwise use real bylines from the filtered live articles; the byline cards link to the cited story and name its team and publisher. In My Teams, cards must match a selected team. In Discovery, cards come from league-wide coverage and respect the selected league. Cards are hidden in Rumors and Saved views. Add real, reviewed profiles to public/featured-writers.json using the shape and criteria in FEATURED_WRITERS.md.

## Saved stories

Signed-in users' bookmarks are stored per account in fanoptic_saved_stories. Signed-out visitors' bookmarks remain in that browser's local storage.
