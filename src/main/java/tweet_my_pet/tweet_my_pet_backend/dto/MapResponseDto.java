package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.Builder;
import lombok.Getter;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.StoreCategory;

@Builder
@Getter
public class MapResponseDto {
    private Long id;
    private String name;
    private String tel;
    private String location;
    private String presidentName;
    private double latitude;
    private double longitude;
    private StoreCategory storeCategory;
    private double rating; // 별점
    private int reviewCount; // 리뷰 개수
    private String thumbPath;

    // StoreFeature 관련 필드 추가
    private boolean isSmallDog;
    private boolean isMediumDog;
    private boolean isLargeDog;
    private boolean isParking;
    private boolean isDogPark;
    private boolean isDogSwimmingPool;
    private boolean isInternet;
    private boolean isBarbecue;
    private boolean isToiletDivision;
    private boolean isFoodPacking;
    private boolean isWaitingPlace;
    private boolean isKidSeat;

    public static MapResponseDto fromCoordinatesAndId(Long id, String name, String location, double latitude, double longitude, StoreCategory storeCategory,
                                                      double rating, int reviewCount,String thumbPath, boolean isSmallDog, boolean isMediumDog,
                                                      boolean isLargeDog, boolean isParking, boolean isDogPark, boolean isDogSwimmingPool,
                                                      boolean isInternet, boolean isBarbecue, boolean isToiletDivision, boolean isFoodPacking,
                                                      boolean isWaitingPlace, boolean isKidSeat) {
        return MapResponseDto.builder()
                .id(id)
                .name(name)
                .location(location)
                .latitude(latitude)
                .longitude(longitude)
                .storeCategory(storeCategory)
                .rating(rating)
                .reviewCount(reviewCount)
                .thumbPath(thumbPath)
                .isSmallDog(isSmallDog)
                .isMediumDog(isMediumDog)
                .isLargeDog(isLargeDog)
                .isParking(isParking)
                .isDogPark(isDogPark)
                .isDogSwimmingPool(isDogSwimmingPool)
                .isInternet(isInternet)
                .isBarbecue(isBarbecue)
                .isToiletDivision(isToiletDivision)
                .isFoodPacking(isFoodPacking)
                .isWaitingPlace(isWaitingPlace)
                .isKidSeat(isKidSeat)
                .build();
    }
}