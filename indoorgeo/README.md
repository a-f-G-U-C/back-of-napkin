# Proposed Geocoding of Indoor Locations
A practical #geocoding scheme for indoor locations is proposed, using 5 elements in order of precision, allowing locations to be identified with progressive resolution, from campus level to asset level.

## Syntax
The five element names are, for the most part, self-explanatory:

    site : block : floor : suite : point

The **site** element is mandatory, everything else is optional. 

The proposed field delimiter is the colon, but another character may be chosen as long as it never appears in the field values.

## SITE
AKA: compound, complex, campus, property, venue, center etc

The location of interest, may consist of several buildings or blocks, as long as they are geographically colocated and linked by the common interest (ownership/management/etc)

Examples: shopping center, hospital, school, residential complex, exhibition center etc

Can be looked up on conventional geocoders and mapped to a global position / footprint - it **anchors** the local position.
It is also the cut-off point of **the expectation of** GPS coverage, even though GPS may remain sporadically available and opportunistically usable.

## BLOCK
AKA: building, tower, wing etc

Has a **footprint**

It’s expected to have consistent floor numbering

## FLOOR
AKA: level, storey etc

It’s expected to have a contiguous floor plan 

has a 3D boundary

It would be nice to be barometrically unambiguous

Usually numbered or labelled

Connected by stairs, elevators, escalators, travelators etc

## SUITE
AKA: apartment, shop, classroom, room (hotel room), office, space etc

Has a boundary

Usually serially numbered (number “on the door”); numbers are unique within the same floor, often within the same block.

## POINT
AKA: POI, point of interest, aisle, room (inside an apartment), cubicle, partition, workstation, asset, equipment etc

Does not necessarily have a boundary, but does have a fixed physical location.

## Examples
- Norwich High School : Block J : L1 : Room 143 : Workstation 2  (all elements)
- Riverside Apartments :: L6 : 608 : Bedroom  (no Block element)
- Criterion Hotel : West Wing : Level 4 : Terrace Bar  (no Point element)
- Westgate Mall : Market Street Tower : LG : ALDI : Dairy  (all elements, commercial)
- Cloverhill Farms : Bobby’s :: Horse Barn : Stall C  (no Floor element)
- Cloverhill Farms : Bobby’s Horse Barn : : : Stall C  (alternative coding)
- Central Station : : Underground 2 : Platform 15 : Car 6  (public transport)
