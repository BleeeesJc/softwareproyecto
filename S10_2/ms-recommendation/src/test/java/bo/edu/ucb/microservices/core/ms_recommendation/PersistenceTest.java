package bo.edu.ucb.microservices.core.ms_recommendation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.data.mongo.DataMongoTest;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.dao.OptimisticLockingFailureException;

import bo.edu.ucb.microservices.core.ms_recommendation.model.Recommendation;
import bo.edu.ucb.microservices.core.ms_recommendation.repository.RecommendationRepository;

@DataMongoTest
public class PersistenceTest extends MongoDbTestBase {

	  @Autowired
	  private RecommendationRepository repository;

	  private Recommendation savedEntity;

	  @BeforeEach
	  void setupDb() {
	    repository.deleteAll().block();

	    Recommendation entity = new Recommendation(1, 2, "a", 3, "c");
	    savedEntity = repository.save(entity).block();

	    assertEqualsRecommendation(entity, savedEntity);
	  }


	  @Test
	  void create() {

	    Recommendation newEntity = new Recommendation(1, 3, "a", 3, "c");
	    repository.save(newEntity).block();

	    Recommendation foundEntity = repository.findById(newEntity.getId()).block();
	    assertEqualsRecommendation(newEntity, foundEntity);

	    assertEquals(2, repository.count().block());
	  }

	  @Test
	  void update() {
	    savedEntity.setAuthor("a2");
	    repository.save(savedEntity).block();

	    Recommendation foundEntity = repository.findById(savedEntity.getId()).block();
	    assertEquals(1, (long)foundEntity.getVersion());
	    assertEquals("a2", foundEntity.getAuthor());
	  }

	  @Test
	  void delete() {
	    repository.delete(savedEntity).block();
	    assertFalse(repository.existsById(savedEntity.getId()).block());
	  }

	  @Test
	  void getByProductId() {
	    List<Recommendation> entityList = repository.findByProductId(savedEntity.getProductId()).collectList().block();

	    assertThat(entityList, hasSize(1));
	    assertEqualsRecommendation(savedEntity, entityList.get(0));
	  }

	  @Test
	  void duplicateError() {
	    assertThrows(DuplicateKeyException.class, () -> {
	      Recommendation entity = new Recommendation(1, 2, "a", 3, "c");
	      repository.save(entity).block();
	    });
	  }

	  @Test
	  void optimisticLockError() {

	    Recommendation entity1 = repository.findById(savedEntity.getId()).block();
	    Recommendation entity2 = repository.findById(savedEntity.getId()).block();

	    entity1.setAuthor("a1");
	    repository.save(entity1).block();

	    assertThrows(OptimisticLockingFailureException.class, () -> {
	      entity2.setAuthor("a2");
	      repository.save(entity2).block();
	    });

	    Recommendation updatedEntity = repository.findById(savedEntity.getId()).block();
	    assertEquals(1, (int)updatedEntity.getVersion());
	    assertEquals("a1", updatedEntity.getAuthor());
	  }

	  private void assertEqualsRecommendation(Recommendation expectedEntity, Recommendation actualEntity) {
	    assertEquals(expectedEntity.getId(),               actualEntity.getId());
	    assertEquals(expectedEntity.getVersion(),          actualEntity.getVersion());
	    assertEquals(expectedEntity.getProductId(),        actualEntity.getProductId());
	    assertEquals(expectedEntity.getRecommendationId(), actualEntity.getRecommendationId());
	    assertEquals(expectedEntity.getAuthor(),           actualEntity.getAuthor());
	    assertEquals(expectedEntity.getRating(),           actualEntity.getRating());
	    assertEquals(expectedEntity.getContent(),          actualEntity.getContent());
	  }
}
