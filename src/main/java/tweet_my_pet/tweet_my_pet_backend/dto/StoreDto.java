package tweet_my_pet.tweet_my_pet_backend.dto;

import lombok.Builder;
import org.springframework.data.geo.Point;
import tweet_my_pet.tweet_my_pet_backend.dto.room.RoomDto;
import tweet_my_pet.tweet_my_pet_backend.dto.room.RoomDto.CreateRoomRequest;
import tweet_my_pet.tweet_my_pet_backend.dto.store.StoreFeatureDto;
import tweet_my_pet.tweet_my_pet_backend.dto.store.StoreFeatureDto.CreateStoreFeatureRequest;
import tweet_my_pet.tweet_my_pet_backend.entity.enums.StoreCategory;
import tweet_my_pet.tweet_my_pet_backend.entity.store.Store;

import java.util.List;

public class StoreDto {
    // 매장 추가 요청
    @Builder
    public record CreateStoreRequest(
            String storeName,
            String storeTel,
            String storeLocation,
            double latitude,
            double longitude,
            String presidentName,
            StoreCategory storeCategory,
            String petGuide,
            String useGuide,
            CreateStoreFeatureRequest feature,
            List<CreateRoomRequest> rooms
    ) {
        public Store toEntity() {
            Point storePoint = new Point(this.latitude(), this.longitude());

            Store store = Store.builder()
                    .storeName(this.storeName)
                    .storeTel(this.storeTel)
                    .storeLocation(this.storeLocation)
                    .storePoint(storePoint)
                    .storePresidentName(this.presidentName)
                    .storeCategory(this.storeCategory)
                    .rating(0.0)
                    .reviewCount(0)
                    .petGuide(this.petGuide)
                    .useGuide(this.useGuide)
                    .storeFeature(this.feature.toEntity())
                    .build();

            this.rooms.stream()
                    .map(roomRequest -> roomRequest.toEntity(store))
                    .forEach(store.getRooms()::add);

            return store;
        }
    }

    // 매장 목록 조회 요청
    @Builder
    public record FetchStoresRequest(
            StoreCategory storeCategory,
            String sort,
            Point point,
            int pageNumber,
            int size
    ) {}

    // 매장 목록 조회 응답
    @Builder
    public record FetchStoresResponse(
            List<StoreDto.FetchStoresResponse.FetchedStore> stores,
            int currentPage,
            int totalPages,
            Long totalElements
    ) {
        @Builder
        public record FetchedStore(
                Long id,
                String storeName,
                String location,
                StoreCategory storeCategory,
                double longitude,
                double latitude,
                double rating,
                int reviewCount,
                double distanceSpacing,
                String feature,
                int lowerPrice
        ) {}
    }

    // 매장 단일 조회 응답
    @Builder
    public record FetchStoreResponse(
            Long id,
            String storeName,
            String storeTel,
            String storeLocation,
            Point storePoint,
            String storePresidentName,
            StoreCategory storeCategory,
            double rating,
            int reviewCount,
            String petGuide,
            String useGuide,
            StoreFeatureDto.FetchStoreFeatureResponse feature,
            List<RoomDto.FetchRoomResponse> rooms
    ) {}
}
